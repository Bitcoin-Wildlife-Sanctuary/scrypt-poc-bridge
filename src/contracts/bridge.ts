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
import { GeneralUtils } from './generalUtils'
import { WithdrawalAggregator, WithdrawalData } from './withdrawalAggregator'


export type BridgeTransaction = {
    ver: ByteString
    inputs: ByteString
    outputContract: ByteString
    accountsRoot: Sha256   // Root hash of accounts tree. Stored in OP_RETURN output.
    depositAggregatorSPK: ByteString     // Aggregator SPK's are separated from the script 
    withdrawalAggregatorSPK: ByteString  // to avoid circular script hashes.
    locktime: ByteString
}

export const MAX_NODES_AGGREGATED = 8

export type AccountData = {
    address: Sha256
    balance: bigint
}

export class Bridge extends SmartContract {
    @prop()
    operator: PubKey

    @prop()
    expanderSPK: ByteString

    constructor(
        operator: PubKey,
        expanderSPK: ByteString
    ) {
        super(...arguments)
        this.operator = operator
        this.expanderSPK = expanderSPK
    }

    @method()
    public deposit(
        shPreimage: SHPreimage,
        sigOperator: Sig,
        prevTx: BridgeTransaction,           // Previous bridge update transaction.
        aggregatorTx: AggregatorTransaction, // Root aggregator transaction.
        feePrevout: ByteString,

        deposits: FixedArray<DepositData, typeof MAX_NODES_AGGREGATED>,
        depositProofs: FixedArray<MerkleProof, typeof MAX_NODES_AGGREGATED>,
        accounts: FixedArray<AccountData, typeof MAX_NODES_AGGREGATED>,
        accountProofs: FixedArray<MerkleProof, typeof MAX_NODES_AGGREGATED>
    ) {
        // Check sighash preimage.
        const s = SigHashUtils.checkSHPreimage(shPreimage)
        assert(this.checkSig(s, SigHashUtils.Gx))

        // Check operator sig.
        assert(this.checkSig(sigOperator, this.operator))

        // Construct prev txids.
        const prevTxId = Bridge.getTxId(prevTx)
        const aggregatorTxId = AggregatorUtils.getTxId(aggregatorTx, false)

        // Check this transaction unlocks specified outputs in the correct order.
        const hashPrevouts = Bridge.getHashPrevouts(
            prevTxId,
            aggregatorTxId,
            feePrevout
        )
        assert(hashPrevouts == shPreimage.hashPrevouts)

        // Make sure this is unlocked via first input.
        assert(shPreimage.inputNumber == toByteString('00000000'))

        // Check second input unlocks correct aggregator script.
        assert(prevTx.depositAggregatorSPK == aggregatorTx.outputContractSPK)

        // Check deposit aggregation result and construct new accounts root.
        let accountsRootNew: Sha256 = prevTx.accountsRoot
        for (let i = 0; i < MAX_NODES_AGGREGATED; i++) {
            const deposit = deposits[i]
            const hashDeposit = DepositAggregator.hashDepositData(deposit)

            // Check Merkle proof of deposit.
            const depositProof = depositProofs[i]
            assert(MerklePath.calcMerkleRoot(hashDeposit, depositProof) == aggregatorTx.hashData)

            // Check deposit goes to an account with the correct address or 
            // an empty account (with a null address).
            const accountDataCurrent = accounts[i]
            assert(
                accountDataCurrent.address == GeneralUtils.NULL_ADDRESS ||
                accountDataCurrent.address == deposit.address
            )

            // Update accounts root hash.
            // 1) Check that the account proof produces current root account hash.
            // 2) Update account data and compute new hash using same proof.
            //    Note, that the account proofs need to be constructed by the operator
            //    in such a way that they already include changes from the previous update.
            //    Order is important here.
            const accountProof = accountProofs[i]
            assert(
                MerklePath.calcMerkleRoot(
                    Bridge.hashAccountData(accountDataCurrent),
                    accountProof
                )
                == accountsRootNew
            )
            const accountDataUpdated: AccountData = {
                address: accountDataCurrent.address,
                balance: accountDataCurrent.balance + deposit.amount
            }
            accountsRootNew = MerklePath.calcMerkleRoot(
                Bridge.hashAccountData(accountDataUpdated),
                accountProof
            )

        }

        // Update acccount state data with new root.
        const accountStateOut = GeneralUtils.getStateOutput(accountsRootNew)
        
        // Also keep OP_RETURN outputs that store aggregator P2TR scripts in the next tx.
        // Because aggregators also reference the bridges P2TR script we store these in separate 
        // outputs instead of the witness script itself because we want to avoid circular hashes.
        const depositAggregatorSPKStateOut = GeneralUtils.getSPKStateOutput(prevTx.depositAggregatorSPK)
        const withdrawalAggregatorSPKStateOut = GeneralUtils.getSPKStateOutput(prevTx.depositAggregatorSPK)

        // Enforce outputs.
        const hashOutputs = sha256(
            prevTx.outputContract +
            accountStateOut +
            depositAggregatorSPKStateOut +
            withdrawalAggregatorSPKStateOut
        )
        assert(hashOutputs == shPreimage.hashOutputs)
    }
    
    @method()
    public withdrawal(
        shPreimage: SHPreimage,
        sigOperator: Sig,
        prevTx: BridgeTransaction,           // Previous bridge update transaction.
        aggregatorTx: AggregatorTransaction, // Root aggregator transaction.
        feePrevout: ByteString,

        withdrawals: FixedArray<WithdrawalData, typeof MAX_NODES_AGGREGATED>,
        withdrawalProofs: FixedArray<MerkleProof, typeof MAX_NODES_AGGREGATED>,
        accounts: FixedArray<AccountData, typeof MAX_NODES_AGGREGATED>,
        accountProofs: FixedArray<MerkleProof, typeof MAX_NODES_AGGREGATED>
    ) {
        // Check sighash preimage.
        const s = SigHashUtils.checkSHPreimage(shPreimage)
        assert(this.checkSig(s, SigHashUtils.Gx))

        // Check operator sig.
        assert(this.checkSig(sigOperator, this.operator))

        // Construct prev txids.
        const prevTxId = Bridge.getTxId(prevTx)
        const aggregatorTxId = AggregatorUtils.getTxId(aggregatorTx, false)

        // Check this transaction unlocks specified outputs in the correct order.
        const hashPrevouts = Bridge.getHashPrevouts(
            prevTxId,
            aggregatorTxId,
            feePrevout
        )
        assert(hashPrevouts == shPreimage.hashPrevouts)

        // Make sure this is unlocked via first input.
        assert(shPreimage.inputNumber == toByteString('00000000'))

        // Check second input unlocks correct aggregator script.
        assert(prevTx.withdrawalAggregatorSPK == aggregatorTx.outputContractSPK)

        // Check withdrawal request aggregation result and construct new accounts root.
        // TODO: Additionally package data for the expander covenant which will pass funds to
        // the requested accounts addresses.
        let accountsRootNew: Sha256 = prevTx.accountsRoot
        for (let i = 0; i < MAX_NODES_AGGREGATED; i++) {
            const withdrawal = withdrawals[i]
            const hashWithdrawal = WithdrawalAggregator.hashWithdrawalData(withdrawal)

            // Check Merkle proof of deposit.
            const withdrawalProof = withdrawalProofs[i]
            assert(MerklePath.calcMerkleRoot(hashWithdrawal, withdrawalProof) == aggregatorTx.hashData)

            // Check withrawal is made for the matching account.
            const accountDataCurrent = accounts[i]
            assert(accountDataCurrent.address == withdrawal.address)

            // Update accounts root hash.
            // 1) Check that the account proof produces current root account hash.
            // 2) Update account data and compute new hash using same proof.
            //    Note, that the account proofs need to be constructed by the operator
            //    in such a way that they already include changes from the previous update.
            //    Order is important here.
            const accountProof = accountProofs[i]
            assert(
                MerklePath.calcMerkleRoot(
                    Bridge.hashAccountData(accountDataCurrent),
                    accountProof
                )
                == accountsRootNew
            )
            const accountDataUpdated: AccountData = {
                address: accountDataCurrent.address,
                balance: accountDataCurrent.balance - withdrawal.amount
            }
            accountsRootNew = MerklePath.calcMerkleRoot(
                Bridge.hashAccountData(accountDataUpdated),
                accountProof
            )
        }

        // Update acccount state data with new root.
        const accountStateOut = GeneralUtils.getStateOutput(accountsRootNew)
        
        // Also keep OP_RETURN outputs that store aggregator P2TR scripts in the next tx.
        // Because aggregators also reference the bridges P2TR script we store these in separate 
        // outputs instead of the witness script itself because we want to avoid circular hashes.
        const depositAggregatorSPKStateOut = GeneralUtils.getSPKStateOutput(prevTx.depositAggregatorSPK)
        const withdrawalAggregatorSPKStateOut = GeneralUtils.getSPKStateOutput(prevTx.depositAggregatorSPK)

        // Enforce outputs.
        const hashOutputs = sha256(
            prevTx.outputContract +
            accountStateOut +
            depositAggregatorSPKStateOut +
            withdrawalAggregatorSPKStateOut
        )
        assert(hashOutputs == shPreimage.hashOutputs)
    }

    @method()
    static hashAccountData(accountData: AccountData): Sha256 {
        return hash256(
            accountData.address + GeneralUtils.padAmt(accountData.balance)
        )
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
