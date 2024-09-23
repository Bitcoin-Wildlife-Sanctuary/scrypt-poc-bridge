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

        // If prev txns are leaves, check that their state data is valid.
        if (isPrevTxLeaf) {
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
        withdrawalAggregatorSPK: ByteString, // SPKs include length prefix!
        feeSPK: ByteString
    ) {
        // Check sighash preimage.
        const s = SigHashUtils.checkSHPreimage(shPreimage)
        assert(this.checkSig(s, SigHashUtils.Gx))

        // Check operator sig.
        assert(this.checkSig(sigOperator, this.operator))

        // Make sure this is unlocked via second input.
        assert(shPreimage.inputNumber == toByteString('01000000'))

        // Make sure first input unlocks bridge covenant.
        assert(len(withdrawalAggregatorSPK) == 35n)
        assert(len(feeSPK) == 23n)
        const hashSpentScripts = sha256(
            this.bridgeSPK + withdrawalAggregatorSPK + feeSPK
        )
        assert(
            hashSpentScripts == shPreimage.hashSpentScripts,
            'hashSpentScript mismatch'
        )

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
