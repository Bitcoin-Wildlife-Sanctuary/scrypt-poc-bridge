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
    FixedArray,
} from 'scrypt-ts'
import { SHPreimage, SigHashUtils } from './sigHashUtils'
import { AggregatorTransaction, AggregatorUtils } from './aggregatorUtils'
import { DepositAggregator, DepositData } from './depositAggregator'
import { MerklePath, MerkleProof } from './merklePath'


export type BridgeTransaction = {
    ver: ByteString
    inputs: ByteString
    outputContract: ByteString
    accountsRoot: ByteString   // Root hash of accounts tree. Stored in OP_RETURN output.
    locktime: ByteString
}

export const MAX_DEPOSITS_AGGREGATED = 8

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
        prevTx: BridgeTransaction,           // Previous bridge update transaction.
        aggregatorTx: AggregatorTransaction, // Root aggregator transaction.
        feePrevout: ByteString,

        deposits: FixedArray<DepositData, typeof MAX_DEPOSITS_AGGREGATED>,
        depositProofs: FixedArray<MerkleProof, typeof MAX_DEPOSITS_AGGREGATED>,
        accountIndexes: FixedArray<bigint, typeof MAX_DEPOSITS_AGGREGATED>
    ) {
        // Check sighash preimage.
        const s = SigHashUtils.checkSHPreimage(shPreimage)
        assert(this.checkSig(s, SigHashUtils.Gx))

        // Check operator sig.
        assert(this.checkSig(sigOperator, this.operator))

        // Construct prev txids.
        const prevTxId = Bridge.getTxId(prevTx)
        const aggregatorTxId = AggregatorUtils.getTxId(aggregatorTx, false)

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

        // Check deposit aggregation result and construct new accounts root.
        let accountsRootNew = prevTx.accountsRoot
        for (let i = 0; i < MAX_DEPOSITS_AGGREGATED; i++) {
            const deposit = deposits[i]
            const hashDeposit = DepositAggregator.hashDepositData(deposit)

            // Check Merkle proof of deposit.
            const depositProof = depositProofs[i]
            assert(MerklePath.calcMerkleRoot(hashDeposit, depositProof) == aggregatorTx.hashData)

            // TODO: Update accounts root hash.
            
        }

        // Update state data
        const stateOut =
            toByteString('00000000000000006a20') + accountsRootNew

        // Enforce outputs.
        const hashOutputs = sha256(
            prevTx.outputContract +
            stateOut
        )
        assert(hashOutputs == shPreimage.hashOutputs, 'hashOutputs mismatch')
    }

    @method()
    static getTxId(tx: BridgeTransaction): Sha256 {
        return hash256(
            tx.ver +
            tx.inputs +
            toByteString('02') +
            tx.outputContract +
            toByteString('000000000000000022') +
            OpCode.OP_RETURN +
            toByteString('20') +
            tx.accountsRoot +
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
