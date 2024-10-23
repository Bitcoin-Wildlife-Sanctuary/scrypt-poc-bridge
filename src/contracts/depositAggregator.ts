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
    Addr
} from 'scrypt-ts'
import { SHPreimage, SigHashUtils } from './sigHashUtils'
import { AggregatorTransaction, AggregatorUtils } from './aggregatorUtils'
import { GeneralUtils } from './generalUtils'


export type DepositData = {
    address: Addr
    amount: bigint
}

export class DepositAggregator extends SmartContract {
    @prop()
    operator: PubKey

    @prop()
    bridgeSPK: ByteString

    /**
     * Covenant used for the aggregation of deposits.
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
     * @param prevTx0 - Transaction data of the first previous transaction being aggregated. Can be a leaf transaction containing the deposit request itself or an already aggregated transaction.
     * @param prevTx1 - Transaction data of the second previous transaction being aggregated.
     * @param ancestorTx0 - First ancestor transaction. These are used to inductively verify the transaction history; ignored when aggregating leaves.
     * @param ancestorTx1 - Second ancestor transaction.
     * @param ancestorTx2 - Third ancestor transaction.
     * @param ancestorTx3 - Fourth ancestor transaction.
     * @param isAncestorLeaf - Indicates whether the ancestor transactions are leaves.
     * @param fundingPrevout - The prevout for the funding UTXO.
     * @param isFirstInput - Indicates whether this method is called from the first or second input.
     * @param depositData0 - Actual deposit data of the first deposit; used when aggregating leaves.
     * @param depositData1 - Actual deposit data of the second deposit; used when aggregating leaves.
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
        fundingPrevout: ByteString,
        isFirstInput: boolean,
        depositData0: DepositData,
        depositData1: DepositData
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
            const hashData0 = DepositAggregator.hashDepositData(depositData0)
            const hashData1 = DepositAggregator.hashDepositData(depositData1)

            assert(hashData0 == prevTx0.hashData)
            assert(hashData1 == prevTx1.hashData)
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

        // Check that the prev outputs actually carry the specified amount 
        // of satoshis. The amount values can also carry aggregated amounts, 
        // in case we're not aggregating leaves anymore.
        assert(
            GeneralUtils.padAmt(depositData0.amount) ==
            prevTx0.outputContractAmt
        )
        assert(
            GeneralUtils.padAmt(depositData1.amount) ==
            prevTx1.outputContractAmt
        )

        // Concatinate hashes from previous aggregation txns (or leaves)
        // and compute new hash. Store this new hash in the state OP_RETURN
        // output.
        const newHash = hash256(prevTx0.hashData + prevTx1.hashData)
        const stateOut = GeneralUtils.getStateOutput(newHash)

        // Sum up aggregated amounts and construct contract output.
        const contractOut = GeneralUtils.getContractOutput(
            depositData0.amount + depositData1.amount,
            prevTx0.outputContractSPK
        )

        // Recurse. Send to aggregator with updated hash.
        const outputs = contractOut + stateOut
        assert(
            sha256(outputs) == shPreimage.hashOutputs
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
    }


    @method()
    static hashDepositData(depositData: DepositData): Sha256 {
        return hash256(
            depositData.address + GeneralUtils.padAmt(depositData.amount)
        )
    }

}
