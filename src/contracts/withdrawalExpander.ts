import { assert, ByteString, hash256, method, prop, PubKey, sha256, Sha256, Sig, SmartContract, toByteString } from "scrypt-ts";
import { SHPreimage, SigHashUtils } from "./sigHashUtils";
import { Bridge, BridgeTransaction } from "./bridge";
import { AggregationData, WithdrawalAggregator, WithdrawalData } from "./withdrawalAggregator";
import { GeneralUtils } from "./generalUtils";


export type ExpanderTransaction = {
    ver: ByteString
    inputContract: ByteString
    inputFee: ByteString
    contractSPK: ByteString
    output0Amt: bigint
    output1Amt: bigint
    hashData: Sha256
    locktime: ByteString
}

export class WithdrawalExpander extends SmartContract {

    @prop()
    operator: PubKey

    constructor(
        operator: PubKey
    ) {
        super(...arguments)
        this.operator = operator
    }


    /**
     * Expands current node of exapnsion tree into further two nodes or leaves.
     * 
     * @param shPreimage - Sighash preimage of the currently executing transaction.
     * @param sigOperator - Signature of bridge operator.
     * @param isExpandingPrevTxFirstOutput - Indicates wether expanding first or second output (i.e. branch).
     * @param isPrevTxBridge - Indicates wether prev tx is the bridge.
     * @param prevTxBridge - Previous bridge tx data. Ignored if prev tx not bridge.
     * @param prevTxExpander - Previous expander tx data. Ignored if prev tx is bridge.
     * @param prevAggregationData - Aggregation data of previous transaction.
     * @param currentAggregationData  - Aggregation data of current trnasaction.
     * @param nextAggregationData0 - Subsequent aggregation data of first branch.
     * @param nextAggregationData1 - Subsequent aggregation data of second branch.
     * @param isExpandingLeaves - Indicates wether we're exapnding into leaves.
     * @param withdrawalData0 - Withdrawal data of fist leaf. Ignored if not expanding into leaves.
     * @param withdrawalData1 - Withdrawal data of second leaf. Ignored if not expanding into leaves.
     * @param fundingPrevout - The prevout for the funding UTXO.
     */
    @method()
    public expand(
        shPreimage: SHPreimage,
        sigOperator: Sig,

        isExpandingPrevTxFirstOutput: boolean,
        isPrevTxBridge: boolean,
        prevTxBridge: BridgeTransaction,
        prevTxExpander: ExpanderTransaction,

        prevAggregationData: AggregationData,
        currentAggregationData: AggregationData,
        nextAggregationData0: AggregationData,
        nextAggregationData1: AggregationData,

        isExpandingLeaves: boolean,
        withdrawalData0: WithdrawalData,
        withdrawalData1: WithdrawalData,

        fundingPrevout: ByteString
    ) {
        // Check sighash preimage.
        const s = SigHashUtils.checkSHPreimage(shPreimage)
        assert(this.checkSig(s, SigHashUtils.Gx))

        // Check operator sig.
        assert(this.checkSig(sigOperator, this.operator))

        // Construct prev tx ID.
        let prevTxId = Sha256(toByteString(''))
        if (isPrevTxBridge) {
            prevTxId = WithdrawalExpander.getBridgeTxId(prevTxBridge)
        } else {
            prevTxId = WithdrawalExpander.getTxId(prevTxExpander)
        }

        // Check passed prev tx is actually unlocked by the currently executing tx.
        const hashPrevouts = WithdrawalExpander.getHashPrevouts(
            prevTxId,
            fundingPrevout,
            isPrevTxBridge
        )
        assert(hashPrevouts == shPreimage.hashPrevouts)

        // Check we're unlocking contract UTXO via the first input.
        assert(shPreimage.inputNumber == toByteString('00000000'))

        // Get root hash from prev txns state output.
        let rootHash = toByteString('')
        if (isPrevTxBridge) {
            rootHash = prevTxBridge.expanderRoot
        } else {
            rootHash = prevTxExpander.hashData
        }
        // Check passed prev aggregation data matches the root hash.
        assert(
            WithdrawalAggregator.hashAggregationData(prevAggregationData) == rootHash
        )

        let hashOutputs = toByteString('')
        if (isExpandingLeaves) {
            // If leaves, check passed withdrawal data matches hashes in prev 
            // aggregation data. Enforce P2WPKH output with the address
            // and amount from this withdrawal data.
            // Address is chosen depending on isExpandingPrevTxFirstOutput.
            if (isExpandingPrevTxFirstOutput) {
                const hashWithdrawalData = WithdrawalAggregator.hashWithdrawalData(withdrawalData0)
                assert(hashWithdrawalData == prevAggregationData.prevH0)
                hashOutputs = sha256(
                    WithdrawalExpander.getP2WPKHOut(
                        GeneralUtils.padAmt(withdrawalData0.amount),
                        withdrawalData0.address
                    )
                )
            } else {
                const hashWithdrawalData = WithdrawalAggregator.hashWithdrawalData(withdrawalData1)
                assert(hashWithdrawalData == prevAggregationData.prevH1)
                hashOutputs = sha256(
                    WithdrawalExpander.getP2WPKHOut(
                        GeneralUtils.padAmt(withdrawalData1.amount),
                        withdrawalData1.address
                    )
                )
            }
        } else {
            // Bring in current aggregation data and check
            // that it matches the hash from the prev aggregation data.
            // Hash is chosen depending on isExpandingPrevTxFirstOutput.
            // If prev tx is the bridge, we only copy the root hash 
            // to be used in the next iteration.
            const hashCurrentAggregationData = WithdrawalAggregator.hashAggregationData(currentAggregationData)
            if (isPrevTxBridge) {
                assert(hashCurrentAggregationData == prevTxBridge.expanderRoot)
            } else if (isExpandingPrevTxFirstOutput) {
                assert(hashCurrentAggregationData == prevAggregationData.prevH0)
            } else {
                assert(hashCurrentAggregationData == prevAggregationData.prevH1)
            }

            // Bring in 2x next aggregation data for both branches.
            // Check that they both hash to the hashes in current aggregation data.
            // Extract amounts from these two and enforce two new expander outputs
            // and a state with the hash of the current aggregation data.
            const hashNextAggregationData0 = WithdrawalAggregator.hashAggregationData(nextAggregationData0)
            const hashNextAggregationData1 = WithdrawalAggregator.hashAggregationData(nextAggregationData1)
            assert(hashNextAggregationData0 == currentAggregationData.prevH0)
            assert(hashNextAggregationData1 == currentAggregationData.prevH1)

            let expanderSPK = prevTxExpander.contractSPK
            if (isPrevTxBridge) {
                expanderSPK = prevTxBridge.expanderSPK
            }

            hashOutputs = sha256(
                GeneralUtils.getContractOutput(nextAggregationData0.sumAmt, expanderSPK) +
                GeneralUtils.getContractOutput(nextAggregationData1.sumAmt, expanderSPK) +
                GeneralUtils.getStateOutput(hashCurrentAggregationData)
            )

        }

        assert(
            hashOutputs == shPreimage.hashOutputs
        )
    }

    @method()
    static getTxId(tx: ExpanderTransaction): Sha256 {
        return hash256(
            tx.ver +
            toByteString('02') +
            tx.inputContract +
            tx.inputFee +
            toByteString('03') +
            GeneralUtils.getContractOutput(tx.output0Amt, tx.contractSPK) +
            GeneralUtils.getContractOutput(tx.output1Amt, tx.contractSPK) +
            GeneralUtils.getStateOutput(tx.hashData) +
            tx.locktime
        )
    }

    @method()
    static getBridgeTxId(tx: BridgeTransaction): Sha256 {
        const stateHash = Bridge.getStateHash(
            tx.accountsRoot, tx.depositAggregatorSPK, tx.withdrawalAggregatorSPK, tx.expanderRoot
        )
        return hash256(
            tx.ver +
            tx.inputs +
            toByteString('03') +
            GeneralUtils.getContractOutput(tx.contractAmt, tx.contractSPK) +
            GeneralUtils.getStateOutput(stateHash) +
            GeneralUtils.getContractOutput(tx.expanderAmt, tx.expanderSPK) +
            tx.locktime
        )
    }

    @method()
    static getHashPrevouts(
        txId: Sha256,
        feePrevout: ByteString,
        isPrevTxBridge: boolean
    ): Sha256 {
        const contractOutIdx = isPrevTxBridge ? toByteString('02000000') : toByteString('00000000')
        return sha256(
            txId +
            contractOutIdx +
            feePrevout
        )
    }

    @method()
    static getP2WPKHOut(
        amount: ByteString,
        addr: ByteString
    ): ByteString {
        return amount + toByteString('160014') + addr
    }

}