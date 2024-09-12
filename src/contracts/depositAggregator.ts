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
    int2ByteString,
} from 'scrypt-ts'
import { SHPreimage, SigHashUtils } from './sigHashUtils'

export type AggregatorTransaction = {
    ver: ByteString
    inputContract: ByteString
    inputFee: ByteString
    outputContractAmt: ByteString
    outputContractSPK: ByteString
    hashData: ByteString    // Hash of state data, stored in OP_RETURN output.
    locktime: ByteString
}

export type DepositData = {
    // TODO: Also add index of slot in bridges account tree?
    address: Sha256,
    amount: bigint
}

export class DepositAggregator extends SmartContract {

    @prop()
    operator: PubKey

    @prop()
    toStateTxSPK: ByteString

    /**
     * Covenant used for the aggregation of deposits.
     * 
     * @param operator - Public key of bridge operator.
     * @param toStateTxSPK - P2TR script of the bridge state covenant.
     */
    constructor(
        operator: PubKey,
        toStateTxSPK: ByteString
    ) {
        super(...arguments)
        this.operator = operator
        this.toStateTxSPK = toStateTxSPK
    }

    @method()
    public propagate(
        shPreimage: SHPreimage,

        isPrevTxLeaf: boolean,  // Marks if prev txns are leaves.
        isFinal: boolean,       // Marks this aggregation call as the final and pays to bridge state covenant.
        sigOperator: Sig,       // Signature of the bridge operator.

        prevTx0: AggregatorTransaction,   // Transaction data of the two prev txns being aggregated. 
        prevTx1: AggregatorTransaction,   // Can either be a leaf tx containing the deposit request itself,
                                    // or already an aggregation tx.

        feePrevout: ByteString,
        isFirstInput: boolean,      // Sets wether this call is made from the first or second input.
        
        depositData0: DepositData,    // Contains actual data of deposit. Used when aggregating leaves.
        depositData1: DepositData 
    ) {
        // Check sighash preimage.
        const s = SigHashUtils.checkSHPreimage(shPreimage)
        assert(this.checkSig(s, SigHashUtils.Gx))

        // Check operator sig.
        assert(this.checkSig(sigOperator, this.operator))

        // Construct prev txids.
        const prevTxId0 = DepositAggregator.getTxId(prevTx0)
        const prevTxId1 = DepositAggregator.getTxId(prevTx1)

        // Validate prev txns.
        const hashPrevouts = DepositAggregator.getHashPrevouts(prevTxId0, prevTxId1, feePrevout)
        assert(hashPrevouts == shPreimage.hashPrevouts, 'hashPrevouts mismatch')
        assert(prevTx0.outputContractSPK == prevTx1.outputContractSPK, 'prev out script mismatch')
        if (isFirstInput) {
            assert(shPreimage.inputNumber == toByteString('00000000'))
        } else {
            assert(shPreimage.inputNumber == toByteString('01000000'))
        }
        
        // If prev txns are leaves, check that their state data is valid.
        if (isPrevTxLeaf) {
            const hashData0 = DepositAggregator.hashDepositData(depositData0)
            const hashData1 = DepositAggregator.hashDepositData(depositData1)
            
            assert(hashData0 == prevTx0.hashData)
            assert(hashData1 == prevTx0.hashData)

            assert(int2ByteString(depositData0.amount) == prevTx0.outputContractAmt)  // TODO: Pad amount with zeroes.
            assert(int2ByteString(depositData1.amount) == prevTx1.outputContractAmt)  // TODO: Pad amount with zeroes.
        }
    
        // Hash the hashes from the previous aggregation txns or leaves.
        const newHash = hash256(prevTx0.hashData + prevTx1.hashData)
        const stateOut = toByteString('0000000000000000') + OpCode.OP_RETURN + newHash // TODO: len prefix?
        
        const outAmt = int2ByteString(depositData0.amount + depositData1.amount) // TODO: Pad amount with zeroes.

        // Enforce outputs.
        let outputs = toByteString('')
        if (isFinal) {
            // Send to state tx.
            outputs +=
                outAmt
                this.toStateTxSPK +
                stateOut
        } else {
            // Recurse. Send to aggregator with updated hash.
            outputs +=
                outAmt
                prevTx0.outputContractSPK +
                stateOut
        }
        
        assert(sha256(outputs) == shPreimage.hashOutputs, 'hashOutputs mismatch')
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
            toByteString('0000000000000000') + OpCode.OP_RETURN + tx.hashData +  // TODO: len prefix?
            tx.locktime
        )
    }

    @method()
    static getHashPrevouts(
        txId0: Sha256,
        txId1: Sha256,
        feePrevout: ByteString
    ): Sha256 {
        return sha256(
            txId0 + toByteString('00000000') +
            txId1 + toByteString('00000000') +
            feePrevout
        )
    }
    
    @method()
    static hashDepositData(depositData: DepositData): Sha256 {
        return hash256(
            depositData.address +
            int2ByteString(depositData.amount)   // TODO: Pad with zeroes?
        )
    }

}