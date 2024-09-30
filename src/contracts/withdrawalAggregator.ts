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
    Sha256
} from 'scrypt-ts'
import { SHPreimage, SigHashUtils } from './sigHashUtils'
import { AggregatorTransaction, AggregatorUtils } from './aggregatorUtils'
import { GeneralUtils } from './generalUtils'


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

    /**
     * Aggregates two aggregator transactions (or leaves) into one.
     *
     * @param shPreimage - Sighash preimage of the currently executing transaction.
     * @param isPrevTxLeaf - Indicates whether the previous transactions are leaves.
     * @param sigOperator - Signature of the bridge operator.
     * @param prevTx0 - Transaction data of the first previous transaction being aggregated.
     * @param prevTx1 - Transaction data of the second previous transaction being aggregated. Can be a leaf transaction containing the withdrawal request itself or an already aggregated transaction.
     * @param ancestorTx0 - First ancestor transaction. These are used to inductively verify the transaction history; ignored when aggregating leaves.
     * @param ancestorTx1 - Second ancestor transaction.
     * @param ancestorTx2 - Third ancestor transaction.
     * @param ancestorTx3 - Fourth ancestor transaction.
     * @param isAncestorLeaf - Indicates whether the ancestor transactions are leaves.
     * @param ownProofTx0 - Transaction that funded `prevTx0`; used to prove control of the withdrawal address.
     * @param ownProofTx1 - Transaction that funded `prevTx1`; used to prove control of the withdrawal address.
     * @param fundingPrevout - The prevout for the funding UTXO.
     * @param isFirstInput - Indicates whether this method is called from the first or second input.
     * @param withdrawalData0 - Actual data of the first withdrawal request; used when aggregating leaves.
     * @param withdrawalData1 - Actual data of the second withdrawal request; used when aggregating leaves.
     */
    @method()
    public aggregate(
        shPreimage: SHPreimage,
        isPrevTxLeaf: boolean,
        sigOperator: Sig,
        prevTx0: AggregatorTransaction,
        prevTx1: AggregatorTransaction,
        ancestorTx0: AggregatorTransaction,
        ancestorTx1: AggregatorTransaction,
        ancestorTx2: AggregatorTransaction,
        ancestorTx3: AggregatorTransaction,
        isAncestorLeaf: boolean,
        ownProofTx0: OwnershipProofTransaction,
        ownProofTx1: OwnershipProofTransaction,
        fundingPrevout: ByteString,
        isFirstInput: boolean,
        withdrawalData0: WithdrawalData,
        withdrawalData1: WithdrawalData
    ) {
        // Check sighash preimage.
        const s = SigHashUtils.checkSHPreimage(shPreimage)
        assert(this.checkSig(s, SigHashUtils.Gx))

        // Check operator sig.
        assert(this.checkSig(sigOperator, this.operator))

        // Construct prev tx IDs.
        const prevTxId0 = AggregatorUtils.getTxId(prevTx0, isPrevTxLeaf)
        const prevTxId1 = AggregatorUtils.getTxId(prevTx1, isPrevTxLeaf)

        // Check passed prev txns are actually unlocked by the currently executing tx.
        const hashPrevouts = AggregatorUtils.getHashPrevouts(
            prevTxId0,
            prevTxId1,
            fundingPrevout
        )
        assert(hashPrevouts == shPreimage.hashPrevouts)
        
        // Check prev txns SPK match.
        assert(prevTx0.outputContractSPK == prevTx1.outputContractSPK)
        
        // Check isFirstInput flag is valid.
        if (isFirstInput) {
            assert(shPreimage.inputNumber == toByteString('00000000'))
        } else {
            assert(shPreimage.inputNumber == toByteString('01000000'))
        }

        if (isPrevTxLeaf) {
            // If prev txns are leaves, check that the hash in their state
            // OP_RETURN output corresponds to the data passed in as witnesses.
            const hashData0 = WithdrawalAggregator.hashWithdrawalData(withdrawalData0)
            const hashData1 = WithdrawalAggregator.hashWithdrawalData(withdrawalData1)

            assert(hashData0 == prevTx0.hashData)
            assert(hashData1 == prevTx0.hashData)

            // Construct ownership proof txids.
            const ownershipProofTxId0 = WithdrawalAggregator.getOwnershipProofTxId(ownProofTx0)
            const ownershipProofTxId1 = WithdrawalAggregator.getOwnershipProofTxId(ownProofTx1)

            // Check leaves actually unlock passed ownership proof txns.
            // Input structure: ownershipProofTxId + output index (0000000000) + nSequence (ffffffff)
            assert(ownershipProofTxId0 + toByteString('0000000000ffffffff') == prevTx0.inputFee)
            assert(ownershipProofTxId1 + toByteString('0000000000ffffffff') == prevTx1.inputFee)

            // Check withdrawal data addresses are the same as ownership proof txns payed to.
            assert(withdrawalData0.address == ownProofTx0.outputAddrP2WPKH)
            assert(withdrawalData1.address == ownProofTx1.outputAddrP2WPKH)
        } else {
            // If we're higher up the aggregation tree, we need to check ancestor
            // transactions in order to inductively validate the whole tree.
            const ancestorTxId0 = AggregatorUtils.getTxId(ancestorTx0, isAncestorLeaf)
            const ancestorTxId1 = AggregatorUtils.getTxId(ancestorTx1, isAncestorLeaf)
            const ancestorTxId2 = AggregatorUtils.getTxId(ancestorTx2, isAncestorLeaf)
            const ancestorTxId3 = AggregatorUtils.getTxId(ancestorTx3, isAncestorLeaf)

            // Check prevTx0 unlocks ancestorTx0 and ancestorTx1.
            // Input structure: ancestorTxId + output index (0000000000) + nSequence (ffffffff)
            assert(prevTx0.inputContract0 == ancestorTxId0 + toByteString('0000000000ffffffff'))
            assert(prevTx0.inputContract1 == ancestorTxId1 + toByteString('0000000000ffffffff'))

            // Check prevTx1 unlocks ancestorTx2 and ancestorTx3.
            assert(prevTx1.inputContract0 == ancestorTxId2 + toByteString('0000000000ffffffff'))
            assert(prevTx1.inputContract1 == ancestorTxId3 + toByteString('0000000000ffffffff'))

            // Check ancestors have same contract SPK as prev txns.
            // This completes the inductive step, since the successfull evaluation 
            // of the ancestors contract SPK also checked its ancestors.
            assert(prevTx0.outputContractSPK == ancestorTx0.outputContractSPK)
            assert(prevTx0.outputContractSPK == ancestorTx1.outputContractSPK)
            assert(prevTx0.outputContractSPK == ancestorTx2.outputContractSPK)
            assert(prevTx0.outputContractSPK == ancestorTx3.outputContractSPK)
        }

        // Concatinate hashes from previous aggregation txns (or leaves)
        // and compute new hash. Store this new hash in the state OP_RETURN
        // output.
        const newHash = hash256(prevTx0.hashData + prevTx1.hashData)
        const stateOut = GeneralUtils.getStateOutput(newHash)

        // Construct contract output. Withdrawal aggregation needs only to carry
        // the minimum dust amount.
        const contractOut = GeneralUtils.getContractOutput(
            546n,
            prevTx0.outputContractSPK
        )

        // Recurse. Send to aggregator with updated hash.
        const outputs = contractOut + stateOut
        assert(
            sha256(outputs) == shPreimage.hashOutputs,
        )
    }

    /**
     * Finalizes the aggregation process by merging the aggregation result into the bridge covenant.
     *
     * @param shPreimage - Sighash preimage of the currently executing transaction.
     * @param sigOperator - Signature of the bridge operator.
     * @param prevTx - The previous aggregator transaction.
     * @param ancestorTx0 - First ancestor transaction. These are used to inductively verify the transaction history.
     * @param ancestorTx1 - Second ancestor transaction.
     * @param bridgeTxId - TXID of the latest bridge instance.
     * @param fundingPrevout - Prevout of funding UTXO.
     */
    @method()
    public finalize(
        shPreimage: SHPreimage,
        sigOperator: Sig,
        prevTx: AggregatorTransaction,
        ancestorTx0: AggregatorTransaction,
        ancestorTx1: AggregatorTransaction,
        bridgeTxId: Sha256,
        fundingPrevout: ByteString
    ) {
        // Check sighash preimage.
        const s = SigHashUtils.checkSHPreimage(shPreimage)
        assert(this.checkSig(s, SigHashUtils.Gx))

        // Check operator sig.
        assert(this.checkSig(sigOperator, this.operator))

        // Construct prev TX ID.
        const prevTxId = AggregatorUtils.getTxId(prevTx, false)

        // Check this transaction unlocks specified outputs in the correct order.
        const hashPrevouts = AggregatorUtils.getHashPrevouts(
            bridgeTxId,
            prevTxId,
            fundingPrevout
        )
        assert(hashPrevouts == shPreimage.hashPrevouts)

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
            withdrawalData.address + GeneralUtils.padAmt(withdrawalData.amount)
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
