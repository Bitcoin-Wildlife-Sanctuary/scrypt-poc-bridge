// @ts-ignore
import btc = require('bitcore-lib-inquisition');
import { Tap } from '@cmdcode/tapscript'  // Requires node >= 19

import * as dotenv from 'dotenv';
dotenv.config();

import { expect, use } from 'chai'
import chaiAsPromised from 'chai-as-promised'
use(chaiAsPromised)

import { WithdrawalExpander } from '../src/contracts/withdrawalExpander'
import { DepositAggregator, DepositData } from '../src/contracts/depositAggregator'
import { AccountData, Bridge, MAX_NODES_AGGREGATED } from '../src/contracts/bridge'
import { ByteString, hash256, PubKey, Sha256, toByteString, UTXO } from 'scrypt-ts';
import { DISABLE_KEYSPEND_PUBKEY, fetchP2WPKHUtxos, schnorrTrick } from './utils/txHelper';
import { myAddress, myPrivateKey, myPublicKey } from './utils/privateKey';
import { WithdrawalAggregator, WithdrawalData } from '../src/contracts/withdrawalAggregator';
import { performDepositAggregation } from './depositAggregator.test';
import { MERKLE_PROOF_MAX_DEPTH, MerklePath, MerkleProof, NodePos } from '../src/contracts/merklePath';
import { GeneralUtils } from '../src/contracts/generalUtils';
import { buildMerkleTree, MerkleTree } from './utils/merkleTree';
import { performWithdrawalAggregation } from './withdrawalAggregator.test';


export function initAccountsTree(accountsData: AccountData[]): MerkleTree {
    if (accountsData.length !== Math.pow(2, MERKLE_PROOF_MAX_DEPTH)) {
        throw new Error('Invalid length of accounts data.')
    }

    const leaves = accountsData.map(data => Bridge.hashAccountData(data))

    const tree = new MerkleTree();
    buildMerkleTree(leaves, tree);

    return tree
}

function prepareDepositsWitnessArray(deposits: DepositData[]): Buffer[] {
    const res: Buffer[] = []

    for (const deposit of deposits) {
        let depositAddressBuff = Buffer.from(deposit.address, 'hex')
        let depositAmtBuff = Buffer.alloc(2) // Bigint witnesses need to be minimally encoded! TODO: Do this automatically.
        depositAmtBuff.writeInt16LE(Number(deposit.amount))

        res.push(depositAddressBuff)
        res.push(depositAmtBuff)
    }

    // Pad with empty buffers.
    while (res.length < MAX_NODES_AGGREGATED * 2) {
        res.push(Buffer.from('', 'hex'))
        res.push(Buffer.from('', 'hex'))
    }

    return res
}

function prepareWithdrawalsWitnessArray(withdrawals: WithdrawalData[]): Buffer[] {
    const res: Buffer[] = []

    for (const withdrawal of withdrawals) {
        let withdrawalAddressBuff = Buffer.from(withdrawal.address, 'hex')
        let withdrawalAmtBuff = Buffer.alloc(2) // Bigint witnesses need to be minimally encoded! TODO: Do this automatically.
        withdrawalAmtBuff.writeInt16LE(Number(withdrawal.amount))

        res.push(withdrawalAddressBuff)
        res.push(withdrawalAmtBuff)
    }

    // Pad with empty buffers.
    while (res.length < MAX_NODES_AGGREGATED * 2) {
        res.push(Buffer.from('', 'hex'))
        res.push(Buffer.from('', 'hex'))
    }

    return res
}

function prepareIntermediateSumsArray(
    intermediateSums: ByteString[][],
    leafIndexes: number[]
): Buffer[] {
    let res: Buffer[] = []

    for (let index of leafIndexes) {
        for (let level = 0; level < MERKLE_PROOF_MAX_DEPTH; level++) {
            const parentIndex = Math.floor(index / 2);

            res.push(
                Buffer.from(intermediateSums[level][parentIndex], 'hex')
            )

            index = parentIndex
        }
    }

    return res
}

function prepareAccountsWitnessArray(accounts: AccountData[]): Buffer[] {
    const res: Buffer[] = []

    for (const account of accounts) {
        let accountAddressBuff = Buffer.from(account.address, 'hex')
        let accountBalanceBuff = Buffer.alloc(2) // Bigint witnesses need to be minimally encoded! TODO: Do this automatically.
        accountBalanceBuff.writeInt16LE(Number(account.balance))
        if (account.balance == 0n) {
            accountBalanceBuff = Buffer.from('', 'hex')
        }

        res.push(accountAddressBuff)
        res.push(accountBalanceBuff)
    }

    // Pad with empty buffers.
    while (res.length < MAX_NODES_AGGREGATED * 2) {
        res.push(Buffer.from('', 'hex'))
        res.push(Buffer.from('', 'hex'))
    }

    return res
}

function prepareMerkleProofsWitnessArray(proofs: MerkleProof[]): Buffer[] {
    const res: Buffer[] = []

    for (const proof of proofs) {
        for (const node of Object.values(proof)) {
            res.push(Buffer.from(node.hash, 'hex'))

            if (node.pos == NodePos.Left) {
                res.push(Buffer.from('01', 'hex'))
            } else if (node.pos == NodePos.Right) {
                res.push(Buffer.from('02', 'hex'))
            } else {
                res.push(Buffer.from('', 'hex'))
            }

        }
    }

    // Pad with empty buffers.
    while (res.length < MAX_NODES_AGGREGATED * 2 * MERKLE_PROOF_MAX_DEPTH) {
        for (let i = 0; i < MERKLE_PROOF_MAX_DEPTH; i++) {
            res.push(Buffer.from('', 'hex'))
            res.push(Buffer.from('', 'hex'))
        }
    }

    return res
}

export async function performBridgeDeposit(
    prevBridgeTx: btc.Transaction,
    depositAggregationRes: any,
    fundingUTXO: UTXO,
    accounts: AccountData[],
    accountsTree: MerkleTree,

    scriptBridgeP2TR: btc.Script,
    scriptDepositAggregatorP2TR: btc.Script,
    scriptWithdrawalAggregatorP2TR: btc.Script,
    scriptExpanderP2TR: btc.Script,
    tapleafBridge: string,
    tapleafDepositAggregator: string,
    seckeyOperator: btc.PrivateKey,
    scriptBridge: btc.Script,
    cblockBridge: string,
    scriptDepositAggregator: btc.Script,
    cblockDepositAggregator: string,

    prevTxExpanderRoot = Buffer.from('', 'hex'),
    prevTxExpanderAmt = Buffer.from('', 'hex'),
) {
    let bridgeUTXO = {
        txId: prevBridgeTx.id,
        outputIndex: 0,
        script: scriptBridgeP2TR,
        satoshis: prevBridgeTx.outputs[0].satoshis
    }
    let depositAggregationUTXO = {
        txId: depositAggregationRes.aggregateTx2.id,
        outputIndex: 0,
        script: scriptDepositAggregatorP2TR,
        satoshis: depositAggregationRes.aggregateTx2.outputs[0].satoshis
    }

    // Update accounts root with all deposits.
    // Also get all releavant proofs.
    let accountsCurrent = Array.from(accounts)
    let accountsSlected: AccountData[] = []
    let prevAccountsRoot = accountsTree.getRoot()
    let deposits: DepositData[] = []
    let depositProofs: MerkleProof[] = []
    let accountProofs: MerkleProof[] = []
    for (let i = 0; i < 4; i++) {
        accountsSlected.push(accountsCurrent[i])

        const deposit = depositAggregationRes.depositDataList[i]
        deposits.push(deposit)

        const depositProof = depositAggregationRes.depositTree.getMerkleProof(i)
        depositProofs.push(depositProof)

        const accountProof = accountsTree.getMerkleProof(i)
        accountProofs.push(accountProof)

        accounts[i] = {
            address: deposit.address,
            balance: accounts[i].balance + deposit.amount
        }

        accountsTree.updateLeaf(i, Bridge.hashAccountData(accounts[i]))
    }

    let stateHash = Bridge.getStateHash(
        accountsTree.getRoot(),
        toByteString('22' + scriptDepositAggregatorP2TR.toHex()),
        toByteString('22' + scriptWithdrawalAggregatorP2TR.toHex()),
        toByteString('')
    )
    let opRetScript = new btc.Script(`6a20${stateHash}`)

    const bridgeTx = new btc.Transaction()
        .from(
            [
                bridgeUTXO,
                depositAggregationUTXO,
                fundingUTXO
            ]
        )
        .addOutput(new btc.Transaction.Output({
            satoshis: 546 + depositAggregationUTXO.satoshis,
            script: scriptBridgeP2TR
        }))
        .addOutput(new btc.Transaction.Output({
            satoshis: 0,
            script: opRetScript
        }))
        .sign(myPrivateKey)

    let schnorrTrickDataIn0 = await schnorrTrick(bridgeTx, tapleafBridge, 0)
    let schnorrTrickDataIn1 = await schnorrTrick(bridgeTx, tapleafDepositAggregator, 1)

    let sigOperatorIn0 = btc.crypto.Schnorr.sign(seckeyOperator, schnorrTrickDataIn0.sighash.hash);
    let sigOperatorIn1 = btc.crypto.Schnorr.sign(seckeyOperator, schnorrTrickDataIn1.sighash.hash);

    let prevTxVer = Buffer.alloc(4)
    prevTxVer.writeUInt32LE(prevBridgeTx.version)
    let prevTxLocktime = Buffer.alloc(4)
    prevTxLocktime.writeUInt32LE(prevBridgeTx.nLockTime)
    let prevTxInputs = new btc.encoding.BufferWriter()
    prevTxInputs.writeUInt8(prevBridgeTx.inputs.length)
    for (const input of prevBridgeTx.inputs) {
        input.toBufferWriter(prevTxInputs);
    }
    let prevTxContractAmt = Buffer.alloc(2) // Bigint witnesses need to be minimally encoded! TODO: Do this automatically.
    prevTxContractAmt.writeInt16LE(prevBridgeTx.outputs[0].satoshis)
    let prevTxContractSPK = Buffer.concat([Buffer.from('22', 'hex'), scriptBridgeP2TR.toBuffer()])
    let prevTxExpanderSPK = Buffer.concat([Buffer.from('22', 'hex'), scriptExpanderP2TR.toBuffer()])
    let prevTxAccountsRoot = Buffer.from(prevAccountsRoot, 'hex')

    let aggregateTx = depositAggregationRes.aggregateTx2
    let aggregatorTxVer = Buffer.alloc(4)
    aggregatorTxVer.writeUInt32LE(aggregateTx.version)
    let aggregatorTxLocktime = Buffer.alloc(4)
    aggregatorTxLocktime.writeUInt32LE(aggregateTx.nLockTime)
    let aggregatorTxInputContract0 = new btc.encoding.BufferWriter()
    aggregateTx.inputs[0].toBufferWriter(aggregatorTxInputContract0);
    let aggregatorTxInputContract1 = new btc.encoding.BufferWriter()
    aggregateTx.inputs[1].toBufferWriter(aggregatorTxInputContract1);
    let aggregatorTxInputFee = new btc.encoding.BufferWriter()
    aggregateTx.inputs[2].toBufferWriter(aggregatorTxInputFee);
    let aggregatorTxContractAmt = Buffer.alloc(8)
    aggregatorTxContractAmt.writeUInt32LE(aggregateTx.outputs[0].satoshis)
    let aggregatorTxContractSPK = Buffer.concat([Buffer.from('22', 'hex'), scriptDepositAggregatorP2TR.toBuffer()])
    let aggregatorTxHashData = Buffer.from(depositAggregationRes.depositTree.getRoot(), 'hex')

    let fundingPrevout = new btc.encoding.BufferWriter()
    fundingPrevout.writeReverse(bridgeTx.inputs[2].prevTxId);
    fundingPrevout.writeInt32LE(bridgeTx.inputs[2].outputIndex);

    let witnessesIn0 = [
        schnorrTrickDataIn0.preimageParts.txVersion,
        schnorrTrickDataIn0.preimageParts.nLockTime,
        schnorrTrickDataIn0.preimageParts.hashPrevouts,
        schnorrTrickDataIn0.preimageParts.hashSpentAmounts,
        schnorrTrickDataIn0.preimageParts.hashScripts,
        schnorrTrickDataIn0.preimageParts.hashSequences,
        schnorrTrickDataIn0.preimageParts.hashOutputs,
        schnorrTrickDataIn0.preimageParts.spendType,
        schnorrTrickDataIn0.preimageParts.inputNumber,
        schnorrTrickDataIn0.preimageParts.tapleafHash,
        schnorrTrickDataIn0.preimageParts.keyVersion,
        schnorrTrickDataIn0.preimageParts.codeseparatorPosition,
        schnorrTrickDataIn0.sighash.hash,
        schnorrTrickDataIn0._e,
        Buffer.from([schnorrTrickDataIn0.eLastByte]),

        sigOperatorIn0,

        prevTxVer,
        prevTxInputs.toBuffer(),
        prevTxContractSPK,
        prevTxExpanderSPK,
        prevTxContractAmt,
        prevTxAccountsRoot,
        prevTxExpanderRoot,
        prevTxExpanderAmt,
        Buffer.concat([Buffer.from('22', 'hex'), scriptDepositAggregatorP2TR.toBuffer()]),
        Buffer.concat([Buffer.from('22', 'hex'), scriptWithdrawalAggregatorP2TR.toBuffer()]),
        prevTxLocktime,

        aggregatorTxVer,
        aggregatorTxInputContract0.toBuffer(),
        aggregatorTxInputContract1.toBuffer(),
        aggregatorTxInputFee.toBuffer(),
        aggregatorTxContractAmt,
        aggregatorTxContractSPK,
        aggregatorTxHashData,
        aggregatorTxLocktime,

        fundingPrevout.toBuffer(),

        ...prepareDepositsWitnessArray(deposits),
        ...prepareAccountsWitnessArray(accountsSlected),

        ...prepareMerkleProofsWitnessArray(depositProofs),
        ...prepareMerkleProofsWitnessArray(accountProofs),

        Buffer.from('', 'hex'), // OP_0 - first public method chosen

        scriptBridge.toBuffer(),
        Buffer.from(cblockBridge, 'hex')
    ]

    bridgeTx.inputs[0].witnesses = witnessesIn0

    let ancestorTx0 = depositAggregationRes.aggregateTx0
    let ancestorTx0Ver = Buffer.alloc(4)
    ancestorTx0Ver.writeUInt32LE(ancestorTx0.version)
    let ancestorTx0Locktime = Buffer.alloc(4)
    ancestorTx0Locktime.writeUInt32LE(ancestorTx0.nLockTime)
    let ancestorTx0InputContract0 = new btc.encoding.BufferWriter()
    ancestorTx0.inputs[0].toBufferWriter(ancestorTx0InputContract0);
    let ancestorTx0InputContract1 = new btc.encoding.BufferWriter()
    ancestorTx0.inputs[1].toBufferWriter(ancestorTx0InputContract1);
    let ancestorTx0InputFee = new btc.encoding.BufferWriter()
    ancestorTx0.inputs[2].toBufferWriter(ancestorTx0InputFee);
    let ancestorTx0ContractAmt = Buffer.alloc(8)
    ancestorTx0ContractAmt.writeUInt32LE(ancestorTx0.outputs[0].satoshis)
    let ancestorTx0ContractSPK = Buffer.concat([Buffer.from('22', 'hex'), scriptDepositAggregatorP2TR.toBuffer()])
    let ancestorTx0HashData = Buffer.from(depositAggregationRes.depositTree.levels[1][0], 'hex')

    let ancestorTx1 = depositAggregationRes.aggregateTx1
    let ancestorTx1Ver = Buffer.alloc(4)
    ancestorTx1Ver.writeUInt32LE(ancestorTx1.version)
    let ancestorTx1Locktime = Buffer.alloc(4)
    ancestorTx1Locktime.writeUInt32LE(ancestorTx1.nLockTime)
    let ancestorTx1InputContract0 = new btc.encoding.BufferWriter()
    ancestorTx1.inputs[0].toBufferWriter(ancestorTx1InputContract0);
    let ancestorTx1InputContract1 = new btc.encoding.BufferWriter()
    ancestorTx1.inputs[1].toBufferWriter(ancestorTx1InputContract1);
    let ancestorTx1InputFee = new btc.encoding.BufferWriter()
    ancestorTx1.inputs[2].toBufferWriter(ancestorTx1InputFee);
    let ancestorTx1ContractAmt = Buffer.alloc(8)
    ancestorTx1ContractAmt.writeUInt32LE(ancestorTx1.outputs[0].satoshis)
    let ancestorTx1ContractSPK = Buffer.concat([Buffer.from('22', 'hex'), scriptDepositAggregatorP2TR.toBuffer()])
    let ancestorTx1HashData = Buffer.from(depositAggregationRes.depositTree.levels[1][1], 'hex')

    let witnessesIn1 = [
        schnorrTrickDataIn1.preimageParts.txVersion,
        schnorrTrickDataIn1.preimageParts.nLockTime,
        schnorrTrickDataIn1.preimageParts.hashPrevouts,
        schnorrTrickDataIn1.preimageParts.hashSpentAmounts,
        schnorrTrickDataIn1.preimageParts.hashScripts,
        schnorrTrickDataIn1.preimageParts.hashSequences,
        schnorrTrickDataIn1.preimageParts.hashOutputs,
        schnorrTrickDataIn1.preimageParts.spendType,
        schnorrTrickDataIn1.preimageParts.inputNumber,
        schnorrTrickDataIn1.preimageParts.tapleafHash,
        schnorrTrickDataIn1.preimageParts.keyVersion,
        schnorrTrickDataIn1.preimageParts.codeseparatorPosition,
        schnorrTrickDataIn1.sighash.hash,
        schnorrTrickDataIn1._e,
        Buffer.from([schnorrTrickDataIn1.eLastByte]),

        sigOperatorIn1,

        aggregatorTxVer,
        aggregatorTxInputContract0.toBuffer(),
        aggregatorTxInputContract1.toBuffer(),
        aggregatorTxInputFee.toBuffer(),
        aggregatorTxContractAmt,
        aggregatorTxContractSPK,
        aggregatorTxHashData,
        aggregatorTxLocktime,

        ancestorTx0Ver,
        ancestorTx0InputContract0.toBuffer(),
        ancestorTx0InputContract1.toBuffer(),
        ancestorTx0InputFee.toBuffer(),
        ancestorTx0ContractAmt,
        ancestorTx0ContractSPK,
        ancestorTx0HashData,
        ancestorTx0Locktime,

        ancestorTx1Ver,
        ancestorTx1InputContract0.toBuffer(),
        ancestorTx1InputContract1.toBuffer(),
        ancestorTx1InputFee.toBuffer(),
        ancestorTx1ContractAmt,
        ancestorTx1ContractSPK,
        ancestorTx1HashData,
        ancestorTx1Locktime,

        prevBridgeTx._getHash(),

        fundingPrevout.toBuffer(),

        Buffer.from('01', 'hex'), // OP_1 - second public method chosen

        scriptDepositAggregator.toBuffer(),
        Buffer.from(cblockDepositAggregator, 'hex')
    ]

    bridgeTx.inputs[1].witnesses = witnessesIn1

    return {
        bridgeTx,
        accounts,
        accountsTree
    }
}

export async function performBridgeWithdrawal(
    prevBridgeTx: btc.Transaction,
    withdrawalAggregationRes: any,
    fundingUTXO: UTXO,
    accounts: AccountData[],
    accountsTree: MerkleTree,

    scriptBridgeP2TR: btc.Script,
    scriptDepositAggregatorP2TR: btc.Script,
    scriptWithdrawalAggregatorP2TR: btc.Script,
    scriptExpanderP2TR: btc.Script,
    tapleafBridge: string,
    tapleafWithdrawalAggregator: string,
    seckeyOperator: btc.PrivateKey,
    scriptBridge: btc.Script,
    cblockBridge: string,
    scriptWithdrawalAggregator: btc.Script,
    cblockWithdrawalAggregator: string,

    prevTxExpanderRoot = Buffer.from('', 'hex'),
    prevTxExpanderAmt = Buffer.from('', 'hex'),
) {
    let bridgeUTXO = {
        txId: prevBridgeTx.id,
        outputIndex: 0,
        script: scriptBridgeP2TR,
        satoshis: prevBridgeTx.outputs[0].satoshis
    }
    let withdrawalAggregationUTXO = {
        txId: withdrawalAggregationRes.aggregateTx2.id,
        outputIndex: 0,
        script: scriptWithdrawalAggregatorP2TR,
        satoshis: withdrawalAggregationRes.aggregateTx2.outputs[0].satoshis
    }

    // Update accounts root with all withdrawals.
    // Also get all releavant proofs.
    let accountsCurrent: AccountData[] = Array.from(accounts)
    let accountsSlected: AccountData[] = []
    let prevAccountsRoot = accountsTree.getRoot()
    let withdrawals: WithdrawalData[] = []
    let withdrawalProofs: MerkleProof[] = []
    let accountProofs: MerkleProof[] = []
    let totalAmtWithdrawn = 0n
    for (let i = 0; i < 4; i++) {
        accountsSlected.push(accountsCurrent[i])

        const withdrawal = withdrawalAggregationRes.withdrawalDataList[i]
        withdrawals.push(withdrawal)

        const withdrawalProof = withdrawalAggregationRes.withdrawalTree.getMerkleProof(i)
        withdrawalProofs.push(withdrawalProof)

        const accountProof = accountsTree.getMerkleProof(i)
        accountProofs.push(accountProof)

        accounts[i] = {
            address: accounts[i].address,
            balance: accounts[i].balance - withdrawal.amount
        }

        accountsTree.updateLeaf(i, Bridge.hashAccountData(accounts[i]))

        totalAmtWithdrawn += withdrawal.amount
    }

    let stateHash = Bridge.getStateHash(
        accountsTree.getRoot(),
        toByteString('22' + scriptDepositAggregatorP2TR.toHex()),
        toByteString('22' + scriptWithdrawalAggregatorP2TR.toHex()),
        toByteString(withdrawalAggregationRes.withdrawalTree.getRoot())
    )
    let opRetScript = new btc.Script(`6a20${stateHash}`)

    const bridgeTx = new btc.Transaction()
        .from(
            [
                bridgeUTXO,
                withdrawalAggregationUTXO,
                fundingUTXO
            ]
        )
        .addOutput(new btc.Transaction.Output({
            satoshis: bridgeUTXO.satoshis - Number(totalAmtWithdrawn),
            script: scriptBridgeP2TR
        }))
        .addOutput(new btc.Transaction.Output({
            satoshis: 0,
            script: opRetScript
        }))
        .addOutput(new btc.Transaction.Output({
            satoshis: Number(totalAmtWithdrawn),
            script: scriptExpanderP2TR
        }))
        .sign(myPrivateKey)

    const schnorrTrickDataIn0 = await schnorrTrick(bridgeTx, tapleafBridge, 0)
    const schnorrTrickDataIn1 = await schnorrTrick(bridgeTx, tapleafWithdrawalAggregator, 1)

    const sigOperatorIn0 = btc.crypto.Schnorr.sign(seckeyOperator, schnorrTrickDataIn0.sighash.hash);
    const sigOperatorIn1 = btc.crypto.Schnorr.sign(seckeyOperator, schnorrTrickDataIn1.sighash.hash);

    let prevTxVer = Buffer.alloc(4)
    prevTxVer.writeUInt32LE(prevBridgeTx.version)
    let prevTxLocktime = Buffer.alloc(4)
    prevTxLocktime.writeUInt32LE(prevBridgeTx.nLockTime)
    let prevTxInputs = new btc.encoding.BufferWriter()
    prevTxInputs.writeUInt8(prevBridgeTx.inputs.length)
    for (const input of prevBridgeTx.inputs) {
        input.toBufferWriter(prevTxInputs);
    }
    let prevTxContractAmt = Buffer.alloc(2) // Bigint witnesses need to be minimally encoded! TODO: Do this automatically.
    prevTxContractAmt.writeInt16LE(prevBridgeTx.outputs[0].satoshis)
    let prevTxContractSPK = Buffer.concat([Buffer.from('22', 'hex'), scriptBridgeP2TR.toBuffer()])
    let prevTxExpanderSPK = Buffer.concat([Buffer.from('22', 'hex'), scriptExpanderP2TR.toBuffer()])
    let prevTxAccountsRoot = Buffer.from(prevAccountsRoot, 'hex')

    let aggregateTx = withdrawalAggregationRes.aggregateTx2
    let aggregatorTxVer = Buffer.alloc(4)
    aggregatorTxVer.writeUInt32LE(aggregateTx.version)
    let aggregatorTxLocktime = Buffer.alloc(4)
    aggregatorTxLocktime.writeUInt32LE(aggregateTx.nLockTime)
    let aggregatorTxInputContract0 = new btc.encoding.BufferWriter()
    aggregateTx.inputs[0].toBufferWriter(aggregatorTxInputContract0);
    let aggregatorTxInputContract1 = new btc.encoding.BufferWriter()
    aggregateTx.inputs[1].toBufferWriter(aggregatorTxInputContract1);
    let aggregatorTxInputFee = new btc.encoding.BufferWriter()
    aggregateTx.inputs[2].toBufferWriter(aggregatorTxInputFee);
    let aggregatorTxContractAmt = Buffer.alloc(8)
    aggregatorTxContractAmt.writeUInt32LE(aggregateTx.outputs[0].satoshis)
    let aggregatorTxContractSPK = Buffer.concat([Buffer.from('22', 'hex'), scriptWithdrawalAggregatorP2TR.toBuffer()])
    let aggregatorTxHashData = Buffer.from(withdrawalAggregationRes.withdrawalTree.getRoot(), 'hex')

    let fundingPrevout = new btc.encoding.BufferWriter()
    fundingPrevout.writeReverse(bridgeTx.inputs[2].prevTxId);
    fundingPrevout.writeInt32LE(bridgeTx.inputs[2].outputIndex);

    let witnessesIn0 = [
        schnorrTrickDataIn0.preimageParts.txVersion,
        schnorrTrickDataIn0.preimageParts.nLockTime,
        schnorrTrickDataIn0.preimageParts.hashPrevouts,
        schnorrTrickDataIn0.preimageParts.hashSpentAmounts,
        schnorrTrickDataIn0.preimageParts.hashScripts,
        schnorrTrickDataIn0.preimageParts.hashSequences,
        schnorrTrickDataIn0.preimageParts.hashOutputs,
        schnorrTrickDataIn0.preimageParts.spendType,
        schnorrTrickDataIn0.preimageParts.inputNumber,
        schnorrTrickDataIn0.preimageParts.tapleafHash,
        schnorrTrickDataIn0.preimageParts.keyVersion,
        schnorrTrickDataIn0.preimageParts.codeseparatorPosition,
        schnorrTrickDataIn0.sighash.hash,
        schnorrTrickDataIn0._e,
        Buffer.from([schnorrTrickDataIn0.eLastByte]),

        sigOperatorIn0,

        prevTxVer,
        prevTxInputs.toBuffer(),
        prevTxContractSPK,
        prevTxExpanderSPK,
        prevTxContractAmt,
        prevTxAccountsRoot,
        prevTxExpanderRoot,
        prevTxExpanderAmt,
        Buffer.concat([Buffer.from('22', 'hex'), scriptDepositAggregatorP2TR.toBuffer()]),
        Buffer.concat([Buffer.from('22', 'hex'), scriptWithdrawalAggregatorP2TR.toBuffer()]),
        prevTxLocktime,

        aggregatorTxVer,
        aggregatorTxInputContract0.toBuffer(),
        aggregatorTxInputContract1.toBuffer(),
        aggregatorTxInputFee.toBuffer(),
        aggregatorTxContractAmt,
        aggregatorTxContractSPK,
        aggregatorTxHashData,
        aggregatorTxLocktime,

        fundingPrevout.toBuffer(),

        ...prepareWithdrawalsWitnessArray(withdrawals),
        ...prepareAccountsWitnessArray(accountsSlected),

        ...prepareIntermediateSumsArray(
            withdrawalAggregationRes.intermediateSums,
            [0, 1, 2, 3] // TODO
        ),

        ...prepareMerkleProofsWitnessArray(withdrawalProofs),
        ...prepareMerkleProofsWitnessArray(accountProofs),

        Buffer.from('01', 'hex'), // OP_1 - second public method chosen

        scriptBridge.toBuffer(),
        Buffer.from(cblockBridge, 'hex')
    ]

    bridgeTx.inputs[0].witnesses = witnessesIn0

    let ancestorTx0 = withdrawalAggregationRes.aggregateTx0
    let ancestorTx0Ver = Buffer.alloc(4)
    ancestorTx0Ver.writeUInt32LE(ancestorTx0.version)
    let ancestorTx0Locktime = Buffer.alloc(4)
    ancestorTx0Locktime.writeUInt32LE(ancestorTx0.nLockTime)
    let ancestorTx0InputContract0 = new btc.encoding.BufferWriter()
    ancestorTx0.inputs[0].toBufferWriter(ancestorTx0InputContract0);
    let ancestorTx0InputContract1 = new btc.encoding.BufferWriter()
    ancestorTx0.inputs[1].toBufferWriter(ancestorTx0InputContract1);
    let ancestorTx0InputFee = new btc.encoding.BufferWriter()
    ancestorTx0.inputs[2].toBufferWriter(ancestorTx0InputFee);
    let ancestorTx0ContractAmt = Buffer.alloc(8)
    ancestorTx0ContractAmt.writeUInt32LE(ancestorTx0.outputs[0].satoshis)
    let ancestorTx0ContractSPK = Buffer.concat([Buffer.from('22', 'hex'), scriptWithdrawalAggregatorP2TR.toBuffer()])
    let ancestorTx0HashData = Buffer.from(withdrawalAggregationRes.withdrawalTree.levels[1][0], 'hex')

    let ancestorTx1 = withdrawalAggregationRes.aggregateTx1
    let ancestorTx1Ver = Buffer.alloc(4)
    ancestorTx1Ver.writeUInt32LE(ancestorTx1.version)
    let ancestorTx1Locktime = Buffer.alloc(4)
    ancestorTx1Locktime.writeUInt32LE(ancestorTx1.nLockTime)
    let ancestorTx1InputContract0 = new btc.encoding.BufferWriter()
    ancestorTx1.inputs[0].toBufferWriter(ancestorTx1InputContract0);
    let ancestorTx1InputContract1 = new btc.encoding.BufferWriter()
    ancestorTx1.inputs[1].toBufferWriter(ancestorTx1InputContract1);
    let ancestorTx1InputFee = new btc.encoding.BufferWriter()
    ancestorTx1.inputs[2].toBufferWriter(ancestorTx1InputFee);
    let ancestorTx1ContractAmt = Buffer.alloc(8)
    ancestorTx1ContractAmt.writeUInt32LE(ancestorTx1.outputs[0].satoshis)
    let ancestorTx1ContractSPK = Buffer.concat([Buffer.from('22', 'hex'), scriptWithdrawalAggregatorP2TR.toBuffer()])
    let ancestorTx1HashData = Buffer.from(withdrawalAggregationRes.withdrawalTree.levels[1][1], 'hex')

    let witnessesIn1 = [
        schnorrTrickDataIn1.preimageParts.txVersion,
        schnorrTrickDataIn1.preimageParts.nLockTime,
        schnorrTrickDataIn1.preimageParts.hashPrevouts,
        schnorrTrickDataIn1.preimageParts.hashSpentAmounts,
        schnorrTrickDataIn1.preimageParts.hashScripts,
        schnorrTrickDataIn1.preimageParts.hashSequences,
        schnorrTrickDataIn1.preimageParts.hashOutputs,
        schnorrTrickDataIn1.preimageParts.spendType,
        schnorrTrickDataIn1.preimageParts.inputNumber,
        schnorrTrickDataIn1.preimageParts.tapleafHash,
        schnorrTrickDataIn1.preimageParts.keyVersion,
        schnorrTrickDataIn1.preimageParts.codeseparatorPosition,
        schnorrTrickDataIn1.sighash.hash,
        schnorrTrickDataIn1._e,
        Buffer.from([schnorrTrickDataIn1.eLastByte]),

        sigOperatorIn1,

        aggregatorTxVer,
        aggregatorTxInputContract0.toBuffer(),
        aggregatorTxInputContract1.toBuffer(),
        aggregatorTxInputFee.toBuffer(),
        aggregatorTxContractAmt,
        aggregatorTxContractSPK,
        aggregatorTxHashData,
        aggregatorTxLocktime,

        ancestorTx0Ver,
        ancestorTx0InputContract0.toBuffer(),
        ancestorTx0InputContract1.toBuffer(),
        ancestorTx0InputFee.toBuffer(),
        ancestorTx0ContractAmt,
        ancestorTx0ContractSPK,
        ancestorTx0HashData,
        ancestorTx0Locktime,

        ancestorTx1Ver,
        ancestorTx1InputContract0.toBuffer(),
        ancestorTx1InputContract1.toBuffer(),
        ancestorTx1InputFee.toBuffer(),
        ancestorTx1ContractAmt,
        ancestorTx1ContractSPK,
        ancestorTx1HashData,
        ancestorTx1Locktime,

        prevBridgeTx._getHash(),

        fundingPrevout.toBuffer(),

        Buffer.from('01', 'hex'), // OP_1 - second public method chosen

        scriptWithdrawalAggregator.toBuffer(),
        Buffer.from(cblockWithdrawalAggregator, 'hex')
    ]

    bridgeTx.inputs[1].witnesses = witnessesIn1
    
    return {
        bridgeTx,
        accounts,
        accountProofs
    }
}


describe('Test SmartContract `Bridge`', () => {
    let seckeyOperator
    let pubkeyOperator

    before(async () => {
        seckeyOperator = myPrivateKey
        pubkeyOperator = myPublicKey

        await DepositAggregator.loadArtifact()
        await WithdrawalAggregator.loadArtifact()
        await WithdrawalExpander.loadArtifact()
        await Bridge.loadArtifact()
    })

    it('should pass', async () => {
        // Create WithdrawalExpander instance to get SPK which is used in Bridges constructor.
        const expander = new WithdrawalExpander(
            PubKey(toByteString(pubkeyOperator.toString()))
        )

        const scriptExpander = expander.lockingScript
        const tapleafExpander = Tap.encodeScript(scriptExpander.toBuffer())

        const [tpubkeyExpander, cblockExpander] = Tap.getPubKey(DISABLE_KEYSPEND_PUBKEY, { target: tapleafExpander })
        const scriptExpanderP2TR = new btc.Script(`OP_1 32 0x${tpubkeyExpander}}`)

        // Create Bridge instance.
        const bridge = new Bridge(
            PubKey(toByteString(pubkeyOperator.toString())),
            toByteString('22' + scriptExpanderP2TR.toBuffer().toString('hex'))
        )

        const scriptBridge = bridge.lockingScript
        const tapleafBridge = Tap.encodeScript(scriptBridge.toBuffer())

        const [tpubkeyBridge, cblockBridge] = Tap.getPubKey(DISABLE_KEYSPEND_PUBKEY, { target: tapleafBridge })
        const scriptBridgeP2TR = new btc.Script(`OP_1 32 0x${tpubkeyBridge}}`)

        // Create deposit aggregator instance.
        const depositAggregator = new DepositAggregator(
            PubKey(toByteString(pubkeyOperator.toString())),
            toByteString(scriptBridgeP2TR.toBuffer().toString('hex'))
        )

        const scriptDepositAggregator = depositAggregator.lockingScript
        const tapleafDepositAggregator = Tap.encodeScript(scriptDepositAggregator.toBuffer())

        const [tpubkeyDepositAggregator, cblockDepositAggregator] = Tap.getPubKey(DISABLE_KEYSPEND_PUBKEY, { target: tapleafDepositAggregator })
        const scriptDepositAggregatorP2TR = new btc.Script(`OP_1 32 0x${tpubkeyDepositAggregator}}`)

        // Create withdrawal aggregator instance.
        const withdrawalAggregator = new WithdrawalAggregator(
            PubKey(toByteString(pubkeyOperator.toString())),
            toByteString(scriptBridgeP2TR.toBuffer().toString('hex'))
        )

        const scriptWithdrawalAggregator = withdrawalAggregator.lockingScript
        const tapleafWithdrawalAggregator = Tap.encodeScript(scriptWithdrawalAggregator.toBuffer())

        const [tpubkeyWithdrawalAggregator, cblockWithdrawalAggregator] = Tap.getPubKey(DISABLE_KEYSPEND_PUBKEY, { target: tapleafWithdrawalAggregator })
        const scriptWithdrawalAggregatorP2TR = new btc.Script(`OP_1 32 0x${tpubkeyWithdrawalAggregator}}`)

        ///////////////////////////////////////

        let utxos = await fetchP2WPKHUtxos(myAddress)
        if (utxos.length === 0) {
            throw new Error(`No UTXO's for address: ${myAddress.toString()}`)
        }

        const depositAmounts = [1329n, 1400n, 1500n, 1888n]
        const depositTxFee = 3000

        const depositAggregationRes = await performDepositAggregation(
            utxos, depositAmounts, depositTxFee, scriptDepositAggregatorP2TR, cblockDepositAggregator,
            scriptDepositAggregator, tapleafDepositAggregator, seckeyOperator
        )

        const withdrawalAmounts = [1000n, 800n, 700n, 998n]
        const withdrawalTxFee = 3000

        const withdrawalAggregationRes = await performWithdrawalAggregation(
            utxos, withdrawalAmounts, withdrawalTxFee, scriptWithdrawalAggregatorP2TR, cblockWithdrawalAggregator,
            scriptWithdrawalAggregator, tapleafWithdrawalAggregator, seckeyOperator
        )

        // Create ampty accounts tree.
        const numAccounts = Math.pow(2, MERKLE_PROOF_MAX_DEPTH);
        const accounts: AccountData[] = Array(numAccounts).fill(
            {
                address: GeneralUtils.NULL_ADDRESS,
                balance: 0n
            }
        )
        let accountsTree = initAccountsTree(accounts)

        ///////////////////
        // Deploy bridge //
        ///////////////////
        const txFundsBridge = new btc.Transaction()
            .from(
                utxos
            )
            .to(myAddress, 3000)
            .to(myAddress, 3000)
            .to(myAddress, 3000)
            .change(myAddress)
            .feePerByte(2)
            .sign(myPrivateKey)

        let stateHash = Bridge.getStateHash(
            accountsTree.getRoot(),
            toByteString('22' + scriptDepositAggregatorP2TR.toHex()),
            toByteString('22' + scriptWithdrawalAggregatorP2TR.toHex()),
            toByteString('')
        )
        let opRetScript = new btc.Script(`6a20${stateHash}`)

        let fundingUTXO: UTXO = {
            address: myAddress.toString(),
            txId: txFundsBridge.id,
            outputIndex: 0,
            script: new btc.Script(myAddress),
            satoshis: txFundsBridge.outputs[0].satoshis
        }

        const deployTx = new btc.Transaction()
            .from(fundingUTXO)
            .addOutput(new btc.Transaction.Output({
                satoshis: 546,
                script: scriptBridgeP2TR
            }))
            .addOutput(new btc.Transaction.Output({
                satoshis: 0,
                script: opRetScript
            }))
            .sign(myPrivateKey)

        /////////////////////////////////
        // Deposit aggregation result. //
        /////////////////////////////////
        fundingUTXO = {
            address: myAddress.toString(),
            txId: txFundsBridge.id,
            outputIndex: 1,
            script: new btc.Script(myAddress),
            satoshis: txFundsBridge.outputs[1].satoshis
        }

        const bridgeDepositRes = await performBridgeDeposit(
            deployTx,
            depositAggregationRes,
            fundingUTXO,
            accounts,
            accountsTree,
            scriptBridgeP2TR,
            scriptDepositAggregatorP2TR,
            scriptWithdrawalAggregatorP2TR,
            scriptExpanderP2TR,
            tapleafBridge,
            tapleafDepositAggregator,
            seckeyOperator,
            scriptBridge,
            cblockBridge,
            scriptDepositAggregator,
            cblockDepositAggregator
        )

        // Run locally
        let interpreter = new btc.Script.Interpreter()
        let flags = btc.Script.Interpreter.SCRIPT_VERIFY_WITNESS | btc.Script.Interpreter.SCRIPT_VERIFY_TAPROOT | btc.Script.Interpreter.SCRIPT_VERIFY_DISCOURAGE_OP_SUCCESS
        let res = interpreter.verify(new btc.Script(''), deployTx.outputs[0].script, bridgeDepositRes.bridgeTx, 0, flags, bridgeDepositRes.bridgeTx.inputs[0].witnesses, deployTx.outputs[0].satoshis)
        expect(res).to.be.true
        res = interpreter.verify(new btc.Script(''), depositAggregationRes.aggregateTx2.outputs[0].script, bridgeDepositRes.bridgeTx, 1, flags, bridgeDepositRes.bridgeTx.inputs[1].witnesses, depositAggregationRes.aggregateTx2.outputs[0].satoshis)
        expect(res).to.be.true

        ////////////////////////////////////
        // Withdrawal aggregation result. //
        ////////////////////////////////////
        fundingUTXO = {
            address: myAddress.toString(),
            txId: txFundsBridge.id,
            outputIndex: 2,
            script: new btc.Script(myAddress),
            satoshis: txFundsBridge.outputs[2].satoshis
        }
        
        const bridgeWithdrawalRes = await performBridgeWithdrawal(
            bridgeDepositRes.bridgeTx,
            withdrawalAggregationRes,
            fundingUTXO,
            accounts,
            accountsTree,
            scriptBridgeP2TR,
            scriptDepositAggregatorP2TR,
            scriptWithdrawalAggregatorP2TR,
            scriptExpanderP2TR,
            tapleafBridge,
            tapleafWithdrawalAggregator,
            seckeyOperator,
            scriptBridge,
            cblockBridge,
            scriptWithdrawalAggregator,
            cblockWithdrawalAggregator
        )

        res = interpreter.verify(new btc.Script(''), bridgeDepositRes.bridgeTx.outputs[0].script, bridgeWithdrawalRes.bridgeTx, 0, flags, bridgeWithdrawalRes.bridgeTx.inputs[0].witnesses, bridgeDepositRes.bridgeTx.outputs[0].satoshis)
        expect(res).to.be.true
        res = interpreter.verify(new btc.Script(''), withdrawalAggregationRes.aggregateTx2.outputs[0].script, bridgeWithdrawalRes.bridgeTx, 1, flags, bridgeWithdrawalRes.bridgeTx.inputs[1].witnesses, withdrawalAggregationRes.aggregateTx2.outputs[0].satoshis)
        expect(res).to.be.true
    })

})