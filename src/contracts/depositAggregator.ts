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


export type DepositData = {
    address: Sha256
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

    @method()
    public aggregate(
        shPreimage: SHPreimage,

        isPrevTxLeaf: boolean, // Marks if prev txns are leaves.
        sigOperator: Sig, // Signature of the bridge operator.

        prevTx0: AggregatorTransaction, // Transaction data of the two prev txns being aggregated.
        prevTx1: AggregatorTransaction, // Can either be a leaf tx containing the deposit request itself or already an aggregation tx.

        fundingPrevout: ByteString,
        isFirstInput: boolean,     // Sets wether this call is made from the first or second input.

        depositData0: DepositData, // Contains actual data of deposit. Used when aggregating leaves.
        depositData1: DepositData
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
            const hashData0 = DepositAggregator.hashDepositData(depositData0)
            const hashData1 = DepositAggregator.hashDepositData(depositData1)

            assert(hashData0 == prevTx0.hashData)
            assert(hashData1 == prevTx0.hashData)
        }

        // Check that the prev outputs actually carry
        // the specified amount of satoshis. The amount values
        // can also carry aggregated amounts, in case we're not aggregating
        // leaves anymore.
        assert(
            AggregatorUtils.padAmt(depositData0.amount) ==
            prevTx0.outputContractAmt
        )
        assert(
            AggregatorUtils.padAmt(depositData1.amount) ==
            prevTx1.outputContractAmt
        )

        // Hash the hashes from the previous aggregation txns or leaves.
        const newHash = hash256(prevTx0.hashData + prevTx1.hashData)
        const stateOut =
            toByteString('000000000000000022') +
            OpCode.OP_RETURN +
            toByteString('20') +
            newHash


        const outAmt = AggregatorUtils.padAmt(
            depositData0.amount + depositData1.amount
        )

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
        depositAggregatorSPK: ByteString, // SPKs include length prefix!
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
        assert(len(depositAggregatorSPK) == 35n)
        assert(len(feeSPK) == 23n)
        const hashSpentScripts = sha256(
            this.bridgeSPK + depositAggregatorSPK + feeSPK
        )
        assert(
            hashSpentScripts == shPreimage.hashSpentScripts,
            'hashSpentScript mismatch'
        )

        // TODO: How to also make sure that the main state covenant calls the right "deposit()" method?
        //       I think this has to be done by the state covenant itself. I.e. the state covenant should also
        //       check that when "deposit()" is called, that the second input unlocks a deposit aggregator SPK.
    }

    
    @method()
    static hashDepositData(depositData: DepositData): Sha256 {
        return hash256(
            depositData.address + AggregatorUtils.padAmt(depositData.amount)
        )
    }

}
