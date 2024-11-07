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
    FixedArray,
    Addr,
} from 'scrypt-ts'
import { SHPreimage, SigHashUtils } from './sigHashUtils'
import { AggregatorTransaction, AggregatorUtils } from './aggregatorUtils'
import { DepositAggregator, DepositData } from './depositAggregator'
import { IntermediateValues, MerklePath, MerkleProof } from './merklePath'
import { GeneralUtils } from './generalUtils'
import { WithdrawalAggregator, WithdrawalData } from './withdrawalAggregator'


export type BridgeTransaction = {
    ver: ByteString
    inputs: ByteString
    contractSPK: ByteString
    expanderSPK: ByteString
    contractAmt: bigint
    accountsRoot: Sha256                 // Root hash of accounts tree. Stored in OP_RETURN output.
    expanderRoot: Sha256                 // Root hash of expander tree. Zero bytes if not withdrawal tx.
    expanderAmt: bigint                  // Amount sent to exapander. Zero if not withrawal tx.
    depositAggregatorSPK: ByteString     // Aggregator SPK's are separated from the script 
    withdrawalAggregatorSPK: ByteString  // to avoid circular script hashes.
    locktime: ByteString
}

export const MAX_NODES_AGGREGATED = 4

export type AccountData = {
    address: Addr
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
        fundingPrevout: ByteString,

        deposits: FixedArray<DepositData, typeof MAX_NODES_AGGREGATED>,
        accounts: FixedArray<AccountData, typeof MAX_NODES_AGGREGATED>,

        depositProofs: FixedArray<MerkleProof, typeof MAX_NODES_AGGREGATED>,
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
            fundingPrevout
        )
        assert(hashPrevouts == shPreimage.hashPrevouts)

        // Make sure this is unlocked via first input.
        assert(shPreimage.inputNumber == toByteString('00000000'))

        // Check second input unlocks correct aggregator script.
        assert(prevTx.depositAggregatorSPK == aggregatorTx.outputContractSPK)

        // Check deposit aggregation result and construct new accounts root.
        // Also sum up all deposit amounts.
        let accountsRootNew: Sha256 = prevTx.accountsRoot
        let totalAmtDeposited = 0n
        for (let i = 0; i < MAX_NODES_AGGREGATED; i++) {
            const deposit = deposits[i]
            if (deposit.address != toByteString('')) {
                accountsRootNew = this.applyDeposit(
                    deposits[i], depositProofs[i], aggregatorTx.hashData, accounts[i], accountProofs[i], accountsRootNew
                )
            }
            totalAmtDeposited += deposit.amount
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
        fundingPrevout: ByteString,

        withdrawals: FixedArray<WithdrawalData, typeof MAX_NODES_AGGREGATED>,
        accounts: FixedArray<AccountData, typeof MAX_NODES_AGGREGATED>,

        intermediateSumsArr: FixedArray<IntermediateValues, typeof MAX_NODES_AGGREGATED>,

        withdrawalProofs: FixedArray<MerkleProof, typeof MAX_NODES_AGGREGATED>,
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
            fundingPrevout
        )
        assert(hashPrevouts == shPreimage.hashPrevouts)

        // Make sure this is unlocked via first input.
        assert(shPreimage.inputNumber == toByteString('00000000'))

        // Check second input unlocks correct aggregator script.
        assert(prevTx.withdrawalAggregatorSPK == aggregatorTx.outputContractSPK)

        // Check withdrawal aggregation result and construct new accounts root.
        // Also sum up all deposit withdrawn.
        let accountsRootNew: Sha256 = prevTx.accountsRoot
        let totalAmtWithdrawn = 0n
        for (let i = 0; i < MAX_NODES_AGGREGATED; i++) {
            const withdrawal = withdrawals[i]
            if (withdrawal.address != toByteString('')) {
                accountsRootNew = this.applyWithdrawal(
                    withdrawal, withdrawalProofs[i], intermediateSumsArr[i], aggregatorTx.hashData, accounts[i], accountProofs[i], accountsRootNew
                )
            }
            totalAmtWithdrawn += withdrawal.amount
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
    applyDeposit(
        deposit: DepositData,
        depositProof: MerkleProof,
        aggregationRoot: Sha256,
        accountDataCurrent: AccountData,
        accountProof: MerkleProof,
        accountsRoot: Sha256
    ): Sha256 {
        const hashDeposit = DepositAggregator.hashDepositData(deposit)

        // Check Merkle proof of deposit.
        // TODO: Check if it is more efficient to construct whole deposit tree and check root,
        //       instead of checking individual proofs.
        assert(MerklePath.calcMerkleRoot(hashDeposit, depositProof) == aggregationRoot)

        // Check deposit goes to an account with the correct address or 
        // an empty account (with a null address).
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
        assert(
            MerklePath.calcMerkleRoot(
                Bridge.hashAccountData(accountDataCurrent),
                accountProof
            )
            == accountsRoot
        )

        const accountDataUpdated: AccountData = {
            address: deposit.address,
            balance: accountDataCurrent.balance + deposit.amount
        }

        // Return new accounts root.
        return MerklePath.calcMerkleRoot(
            Bridge.hashAccountData(accountDataUpdated),
            accountProof
        )
    }

    @method()
    applyWithdrawal(
        withdrawal: WithdrawalData,
        withdrawalProof: MerkleProof,
        intermediateSums: IntermediateValues,
        aggregationRoot: Sha256,
        accountDataCurrent: AccountData,
        accountProof: MerkleProof,
        accountsRoot: Sha256
    ): Sha256 {
        const hashWithdrawal = WithdrawalAggregator.hashWithdrawalData(withdrawal)

        // Check Merkle proof of deposit. Intermediate sums of withdrawal amounts
        // are also included. Those are needed in the expansion process.
        assert(
            MerklePath.calcMerkleRootWIntermediateValues(
                hashWithdrawal, withdrawalProof, intermediateSums
            ) == aggregationRoot
        )

        // Check withrawal is made for the matching account.
        assert(accountDataCurrent.address == withdrawal.address)

        // Update accounts root hash.
        // 1) Check that the account proof produces current root account hash.
        // 2) Update account data and compute new hash using same proof.
        //    Note, that the account proofs need to be constructed by the operator
        //    in such a way that they already include changes from the previous update.
        //    Order is important here.
        assert(
            MerklePath.calcMerkleRoot(
                Bridge.hashAccountData(accountDataCurrent),
                accountProof
            )
            == accountsRoot
        )
        const accountDataUpdated: AccountData = {
            address: accountDataCurrent.address,
            balance: accountDataCurrent.balance - withdrawal.amount
        }
        assert(accountDataUpdated.balance >= 0n)
        return MerklePath.calcMerkleRoot(
            Bridge.hashAccountData(accountDataUpdated),
            accountProof
        )
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

        let expanderOut = toByteString('')
        if (tx.expanderRoot != toByteString('')) {
            expanderOut = GeneralUtils.getContractOutput(tx.expanderAmt, tx.expanderSPK)
            assert(tx.expanderSPK == this.expanderSPK)
        }

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
