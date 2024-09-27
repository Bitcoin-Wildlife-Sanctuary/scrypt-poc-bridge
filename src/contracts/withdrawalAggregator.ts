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
    len,
} from 'scrypt-ts'
import { SHPreimage, SigHashUtils } from './sigHashUtils'
import { AggregatorTransaction, AggregatorUtils } from './aggregatorUtils'


export type WithdrawalData = {
    address: Sha256
    amount: bigint
}

export type OwnershipProofTransaction = {
    ver: ByteString
    inputs: ByteString
    outputAmt: ByteString
    outputAddrP2WPKH: ByteString
    locktime: ByteString
}

export class WithdrawalAggregator extends SmartContract {
    @prop()
    operator: PubKey

    @prop()
    bridgeSPK: ByteString

    /**
     * Covenant used for the aggregation of withdrawal requests.
     *
     * @param operator - Public key of bridge operator.
     * @param bridgeSPK - P2TR script of the bridge state covenant. Includes length prefix!
     */
    constructor(operator: PubKey, bridgeSPK: ByteString) {
        super(...arguments)
        this.operator = operator
        this.bridgeSPK = bridgeSPK
    }

    @method()
    public aggregate(
        shPreimage: SHPreimage,

        isPrevTxLeaf: boolean, // Marks if prev txns are leaves.
        sigOperator: Sig, // Signature of the bridge operator.

        prevTx0: AggregatorTransaction, // Transaction data of the two prev txns being aggregated.
        prevTx1: AggregatorTransaction, // Can either be a leaf tx containing the withdrawal request itself or already an aggregation tx.

        ancestorTx0: AggregatorTransaction, // Ancestor transactions need to be checked in order to inductively verify  
        ancestorTx1: AggregatorTransaction, // the whole trees history. Ignored when aggregating leaves.
        ancestorTx2: AggregatorTransaction,
        ancestorTx3: AggregatorTransaction,
        isAncestorLeaf: boolean,  // Marks if ancestor txns are leaves.

        ownProofTx0: OwnershipProofTransaction, // Transaction that funded prevTx0. Used to proof control of withdrawal address.
        ownProofTx1: OwnershipProofTransaction, // Transaction that funded prevTx1.

        fundingPrevout: ByteString,
        isFirstInput: boolean,     // Sets wether this call is made from the first or second input.

        withdrawalData0: WithdrawalData, // Contains actual data of withdrawal request. Used when aggregating leaves.
        withdrawalData1: WithdrawalData
    ) {
        // Check sighash preimage.
        const s = SigHashUtils.checkSHPreimage(shPreimage)
        assert(this.checkSig(s, SigHashUtils.Gx))

        // Check operator sig.
        assert(this.checkSig(sigOperator, this.operator))

        // Construct prev txids.
        const prevTxId0 = AggregatorUtils.getTxId(prevTx0, isPrevTxLeaf)
        const prevTxId1 = AggregatorUtils.getTxId(prevTx1, isPrevTxLeaf)

        // Validate prev txns.
        const hashPrevouts = AggregatorUtils.getHashPrevouts(
            prevTxId0,
            prevTxId1,
            fundingPrevout
        )
        assert(hashPrevouts == shPreimage.hashPrevouts, 'hashPrevouts mismatch')
        assert(
            prevTx0.outputContractSPK == prevTx1.outputContractSPK,
            'prev out script mismatch'
        )
        if (isFirstInput) {
            assert(shPreimage.inputNumber == toByteString('00000000'))
        } else {
            assert(shPreimage.inputNumber == toByteString('01000000'))
        }

        if (isPrevTxLeaf) {
            // If prev txns are leaves, check that their state data is valid.
            const hashData0 = WithdrawalAggregator.hashWithdrawalData(withdrawalData0)
            const hashData1 = WithdrawalAggregator.hashWithdrawalData(withdrawalData1)

            assert(hashData0 == prevTx0.hashData)
            assert(hashData1 == prevTx0.hashData)

            // Construct ownership proof txids.
            const fundingTxId0 = WithdrawalAggregator.getOwnershipProofTxId(ownProofTx0)
            const fundingTxId1 = WithdrawalAggregator.getOwnershipProofTxId(ownProofTx1)

            // Check leaves actually unlock passed funding txns.
            assert(fundingTxId0 + toByteString('0000000000ffffffff') == prevTx0.inputFee)
            assert(fundingTxId1 + toByteString('0000000000ffffffff') == prevTx1.inputFee)

            // Check withdrawal data addresses are the same as funding txns payed to.
            assert(withdrawalData0.address == ownProofTx0.outputAddrP2WPKH)
            assert(withdrawalData1.address == ownProofTx1.outputAddrP2WPKH)
        } else {
            // If higher up the aggregation tree, we need to check ancestor
            // transactions in order to inductively validate the whole tree.
            const ancestorTxId0 = AggregatorUtils.getTxId(ancestorTx0, isAncestorLeaf)
            const ancestorTxId1 = AggregatorUtils.getTxId(ancestorTx1, isAncestorLeaf)
            const ancestorTxId2 = AggregatorUtils.getTxId(ancestorTx2, isAncestorLeaf)
            const ancestorTxId3 = AggregatorUtils.getTxId(ancestorTx3, isAncestorLeaf)

            // Check prevTx0 unlocks ancestorTx0 and ancestorTx1.
            assert(prevTx0.inputContract0 == ancestorTxId0 + toByteString('0000000000ffffffff'))
            assert(prevTx0.inputContract1 == ancestorTxId1 + toByteString('0000000000ffffffff'))

            // Check prevTx1 unlocks ancestorTx2 and ancestorTx3.
            assert(prevTx1.inputContract0 == ancestorTxId2 + toByteString('0000000000ffffffff'))
            assert(prevTx1.inputContract1 == ancestorTxId3 + toByteString('0000000000ffffffff'))

            // Check ancestors have same contract SPK as prev txns.
            assert(prevTx0.outputContractSPK == ancestorTx0.outputContractSPK)
            assert(prevTx0.outputContractSPK == ancestorTx1.outputContractSPK)
            assert(prevTx0.outputContractSPK == ancestorTx2.outputContractSPK)
            assert(prevTx0.outputContractSPK == ancestorTx3.outputContractSPK)
        }

        // Hash the hashes from the previous aggregation txns or leaves.
        const newHash = hash256(prevTx0.hashData + prevTx1.hashData)
        const stateOut =
            toByteString('000000000000000022') +
            OpCode.OP_RETURN +
            toByteString('20') +
            newHash
        const outAmt = toByteString('2202000000000000') // Dust amount.

        // Recurse. Send to aggregator with updated hash.
        const outputs = outAmt + prevTx0.outputContractSPK + stateOut
        assert(
            sha256(outputs) == shPreimage.hashOutputs,
            'hashOutputs mismatch'
        )
        assert(true)
    }

    /**
     * Merges the aggregation result into the bridge covenant.
     */
    @method()
    public finalize(
        shPreimage: SHPreimage,
        sigOperator: Sig, // Signature of the bridge operator.
        
        prevTx: AggregatorTransaction,
        
        ancestorTx0: AggregatorTransaction, // Ancestor transactions need to be checked in order to inductively verify  
        ancestorTx1: AggregatorTransaction, // the whole trees history.
        
        bridgeTxId: Sha256,                 // TXID of latest bridge instance.
        fundingPrevout: ByteString,         // Prevout of input providing the funds to pay for the tx fees.
    ) {
        // Check sighash preimage.
        const s = SigHashUtils.checkSHPreimage(shPreimage)
        assert(this.checkSig(s, SigHashUtils.Gx))

        // Check operator sig.
        assert(this.checkSig(sigOperator, this.operator))
        
        // Construct prev TX ID.
        const prevTxId = AggregatorUtils.getTxId(prevTx, false)

        // Validate prev txns.
        const hashPrevouts = AggregatorUtils.getHashPrevouts(
            bridgeTxId,
            prevTxId,
            fundingPrevout
        )
        assert(hashPrevouts == shPreimage.hashPrevouts, 'hashPrevouts mismatch')

        // Make sure this is unlocked via second input.
        assert(shPreimage.inputNumber == toByteString('01000000'))
        
        // Construct ancestor TX IDs.
        const ancestorTxId0 = AggregatorUtils.getTxId(ancestorTx0, false)
        const ancestorTxId1 = AggregatorUtils.getTxId(ancestorTx1, false)
        
        // Check prevTx unlocks ancestorTx0 and ancestorTx1.
        assert(prevTx.inputContract0 == ancestorTxId0 + toByteString('0000000000ffffffff'))
        assert(prevTx.inputContract1 == ancestorTxId1 + toByteString('0000000000ffffffff'))
        
        // Check ancestors have same contract SPK as prev tx.
        assert(prevTx.outputContractSPK == ancestorTx0.outputContractSPK)
        assert(prevTx.outputContractSPK == ancestorTx1.outputContractSPK)

        // TODO: How to also make sure that the main state covenant calls the right "withdrawal()" method?
        //       I think this has to be done by the state covenant itself. I.e. the state covenant should also
        //       check that when "withdrawal()" is called, that the second input unlocks a withdrawal aggregator SPK.
    }

    @method()
    static hashWithdrawalData(withdrawalData: WithdrawalData): Sha256 {
        return hash256(
            withdrawalData.address + AggregatorUtils.padAmt(withdrawalData.amount)
        )
    }

    @method()
    static getOwnershipProofTxId(tx: OwnershipProofTransaction): Sha256 {
        return hash256(
            tx.ver +
            tx.inputs +
            toByteString('01') + tx.outputAmt + toByteString('160014') + tx.outputAddrP2WPKH +
            tx.locktime
        )
    }

}
