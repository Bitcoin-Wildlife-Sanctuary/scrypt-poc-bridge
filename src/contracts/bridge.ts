import {
    assert,
    hash256,
    method,
    sha256,
    SmartContract,
    toByteString,
    Sig,
    PubKey,
    prop,
    ByteString,
    Sha256,
    OpCode,
} from 'scrypt-ts'
import { SHPreimage, SigHashUtils } from './sigHashUtils'
import { AggregatorTransaction } from './depositAggregator'

export class Bridge extends SmartContract {
    @prop()
    operator: PubKey

    constructor(operator: PubKey) {
        super(...arguments)
        this.operator = operator
    }

    @method()
    public deposit(
        shPreimage: SHPreimage,
        sigOperator: Sig,
        merkleRoot: ByteString, // Updated Merkle root of balances... (len prefixed)

        prevTx: AggregatorTransaction,
        aggregatorTx: AggregatorTransaction,
        feePrevout: ByteString
    ) {
        // Check sighash preimage.
        const s = SigHashUtils.checkSHPreimage(shPreimage)
        assert(this.checkSig(s, SigHashUtils.Gx))

        // Check operator sig.
        assert(this.checkSig(sigOperator, this.operator))

        // Construct prev txids.
        const prevTxId = Bridge.getTxId(aggregatorTx)
        const aggregatorTxId = Bridge.getTxId(aggregatorTx)

        // Validate prev txns.
        const hashPrevouts = Bridge.getHashPrevouts(
            prevTxId,
            aggregatorTxId,
            feePrevout
        )
        assert(hashPrevouts == shPreimage.hashPrevouts, 'hashPrevouts mismatch')
        assert(
            shPreimage.inputNumber == toByteString('00000000'),
            'state covenant must be called via first input'
        )

        // TODO: Check withdraw / deposit aggregation result?

        // Update state data
        const stateOut =
            toByteString('0000000000000000') + OpCode.OP_RETURN + merkleRoot

        // Enforce outputs.
        const hashOutputs = sha256(
            toByteString('2202000000000000') + // 546 sats...
                prevTx.outputContractSPK +
                stateOut
        )
        assert(hashOutputs == shPreimage.hashOutputs, 'hashOutputs mismatch')
    }

    @method()
    static getTxId(tx: AggregatorTransaction): Sha256 {
        return hash256(
            tx.ver +
                tx.inputContract +
                tx.inputFee +
                toByteString('02') +
                tx.outputContractAmt +
                tx.outputContractSPK +
                toByteString('0000000000000000') +
                OpCode.OP_RETURN +
                tx.hashData +
                tx.locktime
        )
    }

    @method()
    static getHashPrevouts(
        prevStateTxId: Sha256,
        aggregatorTxId: Sha256,
        feePrevout: ByteString
    ): Sha256 {
        return sha256(
            prevStateTxId +
                toByteString('00000000') +
                aggregatorTxId +
                toByteString('00000000') +
                feePrevout
        )
    }
}
