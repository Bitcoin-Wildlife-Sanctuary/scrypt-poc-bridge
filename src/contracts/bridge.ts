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
    contractSPK: ByteString
    contractAmt: bigint
    accountsRoot: Sha256                 // Root hash of accounts tree. Stored in OP_RETURN output.
    expanderRoot: Sha256                 // Root hash of expander tree. Zero bytes if not withdrawal tx.
    expanderAmt: bigint                  // Amount sent to exapander. Zero if not withrawal tx.
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
        const prevTxId = this.getTxId(prevTx)
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
        let totalAmtDeposited = 0n
        for (let i = 0; i < MAX_NODES_AGGREGATED; i++) {
            const deposit = deposits[i]
            const hashDeposit = DepositAggregator.hashDepositData(deposit)

            // Add amt to total.
            totalAmtDeposited += deposit.amount

            // Check Merkle proof of deposit.
            // TODO: Check if it is more efficient to construct whole deposit tree and check root,
            //       instead of checking individual proofs.
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

        // Create new contract output.
        // Add total amount deposited to the bridge output balance.
        const contractOut = GeneralUtils.getContractOutput(
            prevTx.contractAmt + totalAmtDeposited, 
            prevTx.contractSPK
        )

        // Create state output with new state hash.
        const stateHash = Bridge.getStateHash(
            accountsRootNew, prevTx.depositAggregatorSPK, prevTx.withdrawalAggregatorSPK, toByteString('')
        )
        const conractStateOut = GeneralUtils.getStateOutput(stateHash)

        // Enforce outputs.
        const hashOutputs = sha256(
            contractOut +
            conractStateOut
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
        const prevTxId = this.getTxId(prevTx)
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
        let accountsRootNew: Sha256 = prevTx.accountsRoot
        let totalAmtWithdrawn = 0n
        for (let i = 0; i < MAX_NODES_AGGREGATED; i++) {
            const withdrawal = withdrawals[i]
            const hashWithdrawal = WithdrawalAggregator.hashWithdrawalData(withdrawal)

            // Add to total amt withrawn.
            totalAmtWithdrawn += withdrawal.amount

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
            assert(accountDataUpdated.balance >= 0n)
            accountsRootNew = MerklePath.calcMerkleRoot(
                Bridge.hashAccountData(accountDataUpdated),
                accountProof
            )
        }

        // Substract total amount withrawn of the bridge output balance.
        const contractOut = GeneralUtils.getContractOutput(
            prevTx.contractAmt - totalAmtWithdrawn,
            prevTx.contractSPK
        )

        // Create state output with new state hash.
        const stateHash = Bridge.getStateHash(
            accountsRootNew, prevTx.depositAggregatorSPK, prevTx.withdrawalAggregatorSPK, aggregatorTx.hashData
        )
        const conractStateOut = GeneralUtils.getStateOutput(stateHash)

        // Create an expander P2TR output which carries the total amount withrawn.
        const expanderOut = GeneralUtils.getContractOutput(
            totalAmtWithdrawn,
            this.expanderSPK
        )

        // Enforce outputs.
        const hashOutputs = sha256(
            contractOut +
            conractStateOut +
            expanderOut
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
    private getTxId(tx: BridgeTransaction): Sha256 {
        const nOutputs = tx.expanderRoot == toByteString('') ?
            toByteString('02') : toByteString('03')
        const stateHash = Bridge.getStateHash(
            tx.accountsRoot, tx.depositAggregatorSPK, tx.withdrawalAggregatorSPK, tx.expanderRoot
        )
        const expanderOut = tx.expanderRoot == toByteString('') ?
            toByteString('') : GeneralUtils.getContractOutput(tx.expanderAmt, this.expanderSPK)

        return hash256(
            tx.ver +
            tx.inputs +
            nOutputs +
            GeneralUtils.getContractOutput(tx.contractAmt, tx.contractSPK) +
            GeneralUtils.getStateOutput(stateHash) +
            expanderOut +
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

    /**
     * Creates bridge state hash, stored in an OP_RETURN output.
     *
     * @param accountsRoot - Merkle root of bridges account tree.
     * @param depositAggregatorSPK - Deposit aggregator SPK.
     * @param withdrawalAggregatorSPK - Withdrawal aggregator SPK.
     * @param expanderRoot - Merkle root for expander covenant. Zero bytes if not withdrawal tx.
     * @returns 
     */
    @method()
    static getStateHash(
        accountsRoot: Sha256,
        depositAggregatorSPK: ByteString,
        withdrawalAggregatorSPK: ByteString,
        expanderRoot: ByteString
    ): Sha256 {
        return hash256(
            accountsRoot + depositAggregatorSPK + withdrawalAggregatorSPK + expanderRoot
        )
    }

}
