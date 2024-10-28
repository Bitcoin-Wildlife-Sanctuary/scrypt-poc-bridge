// @ts-ignore
import btc = require('bitcore-lib-inquisition');
import { Tap } from '@cmdcode/tapscript'  // Requires node >= 19

import * as dotenv from 'dotenv';
dotenv.config();

import { expect, use } from 'chai'
import chaiAsPromised from 'chai-as-promised'
use(chaiAsPromised)

import { AggregationData, WithdrawalAggregator, WithdrawalData } from '../src/contracts/withdrawalAggregator'
import { Bridge } from '../src/contracts/bridge'
import { Addr, ByteString, hash256, PubKey, Sha256, toByteString, UTXO } from 'scrypt-ts';
import { DISABLE_KEYSPEND_PUBKEY, fetchP2WPKHUtxos, schnorrTrick } from './utils/txHelper';
import { myAddress, myPrivateKey, myPublicKey } from './utils/privateKey';
import { buildMerkleTree, MerkleTree } from './utils/merkleTree';
import { GeneralUtils } from '../src/contracts/generalUtils';
import { MERKLE_PROOF_MAX_DEPTH } from '../src/contracts/merklePath';

export function getIntermediateSums(withdrawalDataList: WithdrawalData[]): ByteString[][] {
    const res: ByteString[][] = []

    const nLeaves = 2 ** MERKLE_PROOF_MAX_DEPTH
    let prevAmts = withdrawalDataList.map(withdrawalData => withdrawalData.amount)

    const padding = new Array(nLeaves - prevAmts.length).fill(0n);
    prevAmts = prevAmts.concat(padding)

    for (let level = 0; level < MERKLE_PROOF_MAX_DEPTH; level++) {
        res.push([])

        const newAmts: bigint[] = []

        for (let i = 0; i < prevAmts.length; i += 2) {
            const left = prevAmts[i];
            const right = prevAmts[i + 1];

            res[level].push(
                GeneralUtils.padAmt(left + right)
            )

            newAmts.push(left + right)
        }

        prevAmts = newAmts
    }

    return res
}

export function initWithdrawalTree(withdrawalDataList: WithdrawalData[], intermediateValues: ByteString[][]): MerkleTree {
    const leaves = withdrawalDataList.map(data => WithdrawalAggregator.hashWithdrawalData(data))

    const tree = new MerkleTree();
    buildMerkleTree(leaves, tree, intermediateValues);

    return tree
}

export function createLeafWithdrawalTxns(
    nWithdrawals: number,
    withdrawals: WithdrawalData[],
    fundingUTXOS: UTXO[],
    scriptAggregatorP2TR: btc.Script
) {
    const ownProofTxns: btc.Transaction[] = []
    const leafTxns: btc.Transaction[] = []

    for (let i = 0; i < nWithdrawals; i++) {
        const fundingUTXO = fundingUTXOS[i]

        // Create ownership proof txn.
        const ownProofTx = new btc.Transaction()
            .from(fundingUTXO)
            .to(myAddress, 1100)

        ownProofTxns.push(ownProofTx)

        const ownProofUTXO = {
            address: myAddress.toString(),
            txId: ownProofTx.id,
            outputIndex: 0,
            script: new btc.Script(myAddress),
            satoshis: ownProofTx.outputs[0].satoshis
        }

        const withdrawalData = withdrawals[i]
        const withdrawalDataHash = WithdrawalAggregator.hashWithdrawalData(withdrawalData)
        const opRetScript = new btc.Script(`6a20${withdrawalDataHash}`)

        // Construct leaf txn.
        const leafTx = new btc.Transaction()
            .from(ownProofUTXO)
            .addOutput(new btc.Transaction.Output({
                satoshis: 546,
                script: scriptAggregatorP2TR
            }))
            .addOutput(new btc.Transaction.Output({
                satoshis: 0,
                script: opRetScript
            }))
            .sign(myPrivateKey)

        leafTxns.push(leafTx)
    }

    return {
        ownProofTxns,
        leafTxns
    }
}

export async function mergeWithdrawalLeaves(
    leafTx0: btc.Transaction,
    leafTx1: btc.Transaction,
    ownProofTx0: btc.Transaction,
    ownProofTx1: btc.Transaction,
    fundingUTXO: UTXO,
    withdrawalData0: WithdrawalData,
    withdrawalData1: WithdrawalData,
    withdrawalDataHash0: Sha256,
    withdrawalDataHash1: Sha256,
    scriptAggregatorP2TR: btc.Script,
    tapleafAggregator: string,
    scriptAggregator: btc.Script,
    cblockAggregator: string,
    seckeyOperator: btc.PrivateKey
): Promise<btc.Transaction> {
    let leafTx0UTXO = {
        txId: leafTx0.id,
        outputIndex: 0,
        script: scriptAggregatorP2TR,
        satoshis: leafTx0.outputs[0].satoshis
    }
    let leafTx1UTXO = {
        txId: leafTx1.id,
        outputIndex: 0,
        script: scriptAggregatorP2TR,
        satoshis: leafTx1.outputs[0].satoshis
    }

    const aggregationData0: AggregationData = {
        prevH0: withdrawalDataHash0,
        prevH1: withdrawalDataHash1,
        sumAmt: withdrawalData0.amount + withdrawalData1.amount
    }
    const aggregateHash0 = WithdrawalAggregator.hashAggregationData(
        aggregationData0
    )
    let opRetScript = new btc.Script(`6a20${aggregateHash0}`)

    const aggregateTx = new btc.Transaction()
        .from(
            [
                leafTx0UTXO,
                leafTx1UTXO,
                fundingUTXO
            ]
        )
        .addOutput(new btc.Transaction.Output({
            satoshis: 546,
            script: scriptAggregatorP2TR
        }))
        .addOutput(new btc.Transaction.Output({
            satoshis: 0,
            script: opRetScript
        }))
        .sign(myPrivateKey)

    let schnorrTrickDataIn0 = await schnorrTrick(aggregateTx, tapleafAggregator, 0)
    let schnorrTrickDataIn1 = await schnorrTrick(aggregateTx, tapleafAggregator, 1)

    let sigOperatorIn0 = btc.crypto.Schnorr.sign(seckeyOperator, schnorrTrickDataIn0.sighash.hash);
    let sigOperatorIn1 = btc.crypto.Schnorr.sign(seckeyOperator, schnorrTrickDataIn1.sighash.hash);

    let prevTx0Ver = Buffer.alloc(4)
    prevTx0Ver.writeUInt32LE(leafTx0.version)
    let prevTx0Locktime = Buffer.alloc(4)
    prevTx0Locktime.writeUInt32LE(leafTx0.nLockTime)
    let prevTx0InputFee = new btc.encoding.BufferWriter()
    leafTx0.inputs[0].toBufferWriter(prevTx0InputFee);
    let prevTx0ContractAmt = Buffer.alloc(8)
    prevTx0ContractAmt.writeUInt32LE(leafTx0.outputs[0].satoshis)
    let prevTx0ContractSPK = Buffer.concat([Buffer.from('22', 'hex'), scriptAggregatorP2TR.toBuffer()])
    let prevTx0HashData = withdrawalDataHash0

    let prevTx1Ver = Buffer.alloc(4)
    prevTx1Ver.writeUInt32LE(leafTx1.version)
    let prevTx1Locktime = Buffer.alloc(4)
    prevTx1Locktime.writeUInt32LE(leafTx1.nLockTime)
    let prevTx1InputFee = new btc.encoding.BufferWriter()
    leafTx1.inputs[0].toBufferWriter(prevTx1InputFee);
    let prevTx1ContractAmt = Buffer.alloc(8)
    prevTx1ContractAmt.writeUInt32LE(leafTx1.outputs[0].satoshis)
    let prevTx1ContractSPK = Buffer.concat([Buffer.from('22', 'hex'), scriptAggregatorP2TR.toBuffer()])
    let prevTx1HashData = withdrawalDataHash1

    let ownProofTx0Ver = Buffer.alloc(4)
    ownProofTx0Ver.writeUInt32LE(ownProofTx0.version)
    let ownProofTx0Locktime = Buffer.alloc(4)
    ownProofTx0Locktime.writeUInt32LE(ownProofTx0.nLockTime)
    let ownProofTx0Inputs = new btc.encoding.BufferWriter()
    ownProofTx0Inputs.writeVarintNum(ownProofTx0.inputs.length)
    ownProofTx0.inputs[0].toBufferWriter(ownProofTx0Inputs);
    let ownProofTx0OutputAmt = Buffer.alloc(8)
    ownProofTx0OutputAmt.writeUInt32LE(ownProofTx0.outputs[0].satoshis)
    let ownProofTx0OutputAddrP2WPKH = myAddress.hashBuffer

    let ownProofTx1Ver = Buffer.alloc(4)
    ownProofTx1Ver.writeUInt32LE(ownProofTx1.version)
    let ownProofTx1Locktime = Buffer.alloc(4)
    ownProofTx1Locktime.writeUInt32LE(ownProofTx1.nLockTime)
    let ownProofTx1Inputs = new btc.encoding.BufferWriter()
    ownProofTx1Inputs.writeVarintNum(ownProofTx1.inputs.length)
    ownProofTx1.inputs[0].toBufferWriter(ownProofTx1Inputs);
    let ownProofTx1OutputAmt = Buffer.alloc(8)
    ownProofTx1OutputAmt.writeUInt32LE(ownProofTx1.outputs[0].satoshis)
    let ownProofTx1OutputAddrP2WPKH = myAddress.hashBuffer

    let fundingPrevout = new btc.encoding.BufferWriter()
    fundingPrevout.writeReverse(aggregateTx.inputs[2].prevTxId);
    fundingPrevout.writeInt32LE(aggregateTx.inputs[2].outputIndex);

    let withdrawalData0AddressBuff = Buffer.from(withdrawalData0.address, 'hex')
    let withdrawalData0AmtBuff = Buffer.alloc(2) // Bigint witnesses need to be minimally encoded! TODO: Do this automatically.
    withdrawalData0AmtBuff.writeInt16LE(Number(withdrawalData0.amount))

    let withdrawalData1AddressBuff = Buffer.from(withdrawalData1.address, 'hex')
    let withdrawalData1AmtBuff = Buffer.alloc(2)
    withdrawalData1AmtBuff.writeInt16LE(Number(withdrawalData1.amount))

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

        Buffer.from('01', 'hex'), // is prev tx leaf (true)
        sigOperatorIn0,

        prevTx0Ver,
        Buffer.from('', 'hex'),
        Buffer.from('', 'hex'),
        prevTx0InputFee.toBuffer(),
        prevTx0ContractAmt,
        prevTx0ContractSPK,
        Buffer.from(prevTx0HashData, 'hex'),
        prevTx0Locktime,

        prevTx1Ver,
        Buffer.from('', 'hex'),
        Buffer.from('', 'hex'),
        prevTx1InputFee.toBuffer(),
        prevTx1ContractAmt,
        prevTx1ContractSPK,
        Buffer.from(prevTx1HashData, 'hex'),
        prevTx1Locktime,

        Buffer.from('', 'hex'),
        Buffer.from('', 'hex'),
        Buffer.from('', 'hex'),
        Buffer.from('', 'hex'),
        Buffer.from('', 'hex'),
        Buffer.from('', 'hex'),
        Buffer.from('', 'hex'),
        Buffer.from('', 'hex'),

        Buffer.from('', 'hex'),
        Buffer.from('', 'hex'),
        Buffer.from('', 'hex'),
        Buffer.from('', 'hex'),
        Buffer.from('', 'hex'),
        Buffer.from('', 'hex'),
        Buffer.from('', 'hex'),
        Buffer.from('', 'hex'),

        Buffer.from('', 'hex'),
        Buffer.from('', 'hex'),
        Buffer.from('', 'hex'),
        Buffer.from('', 'hex'),
        Buffer.from('', 'hex'),
        Buffer.from('', 'hex'),
        Buffer.from('', 'hex'),
        Buffer.from('', 'hex'),

        Buffer.from('', 'hex'),
        Buffer.from('', 'hex'),
        Buffer.from('', 'hex'),
        Buffer.from('', 'hex'),
        Buffer.from('', 'hex'),
        Buffer.from('', 'hex'),
        Buffer.from('', 'hex'),
        Buffer.from('', 'hex'),

        Buffer.from('', 'hex'),

        ownProofTx0Ver,
        ownProofTx0Inputs.toBuffer(),
        ownProofTx0OutputAmt,
        ownProofTx0OutputAddrP2WPKH,
        ownProofTx0Locktime,

        ownProofTx1Ver,
        ownProofTx1Inputs.toBuffer(),
        ownProofTx1OutputAmt,
        ownProofTx1OutputAddrP2WPKH,
        ownProofTx1Locktime,

        fundingPrevout.toBuffer(),
        Buffer.from('01', 'hex'), // is first input (true)

        withdrawalData0AddressBuff,
        withdrawalData0AmtBuff,
        withdrawalData1AddressBuff,
        withdrawalData1AmtBuff,

        Buffer.from('', 'hex'),
        Buffer.from('', 'hex'),
        Buffer.from('', 'hex'),
        Buffer.from('', 'hex'),
        Buffer.from('', 'hex'),
        Buffer.from('', 'hex'),

        Buffer.from('', 'hex'), // OP_0 - first public method chosen

        scriptAggregator.toBuffer(),
        Buffer.from(cblockAggregator, 'hex')
    ]
    aggregateTx.inputs[0].witnesses = witnessesIn0

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

        Buffer.from('01', 'hex'), // is prev tx leaf (true)
        sigOperatorIn1,

        prevTx0Ver,
        Buffer.from('', 'hex'),
        Buffer.from('', 'hex'),
        prevTx0InputFee.toBuffer(),
        prevTx0ContractAmt,
        prevTx0ContractSPK,
        Buffer.from(prevTx0HashData, 'hex'),
        prevTx0Locktime,

        prevTx1Ver,
        Buffer.from('', 'hex'),
        Buffer.from('', 'hex'),
        prevTx1InputFee.toBuffer(),
        prevTx1ContractAmt,
        prevTx1ContractSPK,
        Buffer.from(prevTx1HashData, 'hex'),
        prevTx1Locktime,

        Buffer.from('', 'hex'),
        Buffer.from('', 'hex'),
        Buffer.from('', 'hex'),
        Buffer.from('', 'hex'),
        Buffer.from('', 'hex'),
        Buffer.from('', 'hex'),
        Buffer.from('', 'hex'),
        Buffer.from('', 'hex'),

        Buffer.from('', 'hex'),
        Buffer.from('', 'hex'),
        Buffer.from('', 'hex'),
        Buffer.from('', 'hex'),
        Buffer.from('', 'hex'),
        Buffer.from('', 'hex'),
        Buffer.from('', 'hex'),
        Buffer.from('', 'hex'),

        Buffer.from('', 'hex'),
        Buffer.from('', 'hex'),
        Buffer.from('', 'hex'),
        Buffer.from('', 'hex'),
        Buffer.from('', 'hex'),
        Buffer.from('', 'hex'),
        Buffer.from('', 'hex'),
        Buffer.from('', 'hex'),

        Buffer.from('', 'hex'),
        Buffer.from('', 'hex'),
        Buffer.from('', 'hex'),
        Buffer.from('', 'hex'),
        Buffer.from('', 'hex'),
        Buffer.from('', 'hex'),
        Buffer.from('', 'hex'),
        Buffer.from('', 'hex'),

        Buffer.from('', 'hex'),

        ownProofTx0Ver,
        ownProofTx0Inputs.toBuffer(),
        ownProofTx0OutputAmt,
        ownProofTx0OutputAddrP2WPKH,
        ownProofTx0Locktime,

        ownProofTx1Ver,
        ownProofTx1Inputs.toBuffer(),
        ownProofTx1OutputAmt,
        ownProofTx1OutputAddrP2WPKH,
        ownProofTx1Locktime,

        fundingPrevout.toBuffer(),
        Buffer.from('', 'hex'), // is first input (false)

        withdrawalData0AddressBuff,
        withdrawalData0AmtBuff,
        withdrawalData1AddressBuff,
        withdrawalData1AmtBuff,

        Buffer.from('', 'hex'),
        Buffer.from('', 'hex'),
        Buffer.from('', 'hex'),
        Buffer.from('', 'hex'),
        Buffer.from('', 'hex'),
        Buffer.from('', 'hex'),

        Buffer.from('', 'hex'), // OP_0 - first public method chosen

        scriptAggregator.toBuffer(),
        Buffer.from(cblockAggregator, 'hex')
    ]
    aggregateTx.inputs[1].witnesses = witnessesIn1

    return aggregateTx
}

export async function mergeAggregateWithdrawalNodes(
    aggregateTx0: btc.Transaction,
    aggregateTx1: btc.Transaction,
    ancestorTx0: btc.Transaction,
    ancestorTx1: btc.Transaction,
    ancestorTx2: btc.Transaction,
    ancestorTx3: btc.Transaction,
    aggregationData0: AggregationData,
    aggregationData1: AggregationData,
    ancestorTx0HashData: Sha256,
    ancestorTx1HashData: Sha256,
    ancestorTx2HashData: Sha256,
    ancestorTx3HashData: Sha256,
    fundingUTXO: UTXO,
    scriptAggregatorP2TR: btc.Script,
    tapleafAggregator: string,
    scriptAggregator: btc.Script,
    cblockAggregator: string,
    seckeyOperator: btc.PrivateKey
): Promise<btc.Transaction> {
    let aggregateTx0UTXO = {
        txId: aggregateTx0.id,
        outputIndex: 0,
        script: scriptAggregatorP2TR,
        satoshis: aggregateTx0.outputs[0].satoshis
    }
    let aggregateTx1UTXO = {
        txId: aggregateTx1.id,
        outputIndex: 0,
        script: scriptAggregatorP2TR,
        satoshis: aggregateTx1.outputs[0].satoshis
    }

    const aggregateHash0 = WithdrawalAggregator.hashAggregationData(aggregationData0)
    const aggregateHash1 = WithdrawalAggregator.hashAggregationData(aggregationData1)
    const aggregationData2: AggregationData = {
        prevH0: aggregateHash0,
        prevH1: aggregateHash1,
        sumAmt: aggregationData0.sumAmt + aggregationData1.sumAmt
    }
    const aggregateHash2 = WithdrawalAggregator.hashAggregationData(aggregationData2)
    let opRetScript = new btc.Script(`6a20${aggregateHash2}`)

    const aggregateTx2 = new btc.Transaction()
        .from(
            [
                aggregateTx0UTXO,
                aggregateTx1UTXO,
                fundingUTXO
            ]
        )
        .addOutput(new btc.Transaction.Output({
            satoshis: 546,
            script: scriptAggregatorP2TR
        }))
        .addOutput(new btc.Transaction.Output({
            satoshis: 0,
            script: opRetScript
        }))
        .sign(myPrivateKey)

    let schnorrTrickDataIn0 = await schnorrTrick(aggregateTx2, tapleafAggregator, 0)
    let schnorrTrickDataIn1 = await schnorrTrick(aggregateTx2, tapleafAggregator, 1)

    let sigOperatorIn0 = btc.crypto.Schnorr.sign(seckeyOperator, schnorrTrickDataIn0.sighash.hash);
    let sigOperatorIn1 = btc.crypto.Schnorr.sign(seckeyOperator, schnorrTrickDataIn1.sighash.hash);

    let prevTx0Ver = Buffer.alloc(4)
    prevTx0Ver.writeUInt32LE(aggregateTx0.version)
    let prevTx0Locktime = Buffer.alloc(4)
    prevTx0Locktime.writeUInt32LE(aggregateTx0.nLockTime)
    let prevTx0InputContract0 = new btc.encoding.BufferWriter()
    aggregateTx0.inputs[0].toBufferWriter(prevTx0InputContract0);
    let prevTx0InputContract1 = new btc.encoding.BufferWriter()
    aggregateTx0.inputs[1].toBufferWriter(prevTx0InputContract1);
    let prevTx0InputFee = new btc.encoding.BufferWriter()
    aggregateTx0.inputs[2].toBufferWriter(prevTx0InputFee);
    let prevTx0ContractAmt = Buffer.alloc(8)
    prevTx0ContractAmt.writeUInt32LE(aggregateTx0.outputs[0].satoshis)
    let prevTx0ContractSPK = Buffer.concat([Buffer.from('22', 'hex'), scriptAggregatorP2TR.toBuffer()])
    let prevTx0HashData = aggregateHash0

    let prevTx1Ver = Buffer.alloc(4)
    prevTx1Ver.writeUInt32LE(aggregateTx1.version)
    let prevTx1Locktime = Buffer.alloc(4)
    prevTx1Locktime.writeUInt32LE(aggregateTx1.nLockTime)
    let prevTx1InputContract0 = new btc.encoding.BufferWriter()
    aggregateTx1.inputs[0].toBufferWriter(prevTx1InputContract0);
    let prevTx1InputContract1 = new btc.encoding.BufferWriter()
    aggregateTx1.inputs[1].toBufferWriter(prevTx1InputContract1);
    let prevTx1InputFee = new btc.encoding.BufferWriter()
    aggregateTx1.inputs[2].toBufferWriter(prevTx1InputFee);
    let prevTx1ContractAmt = Buffer.alloc(8)
    prevTx1ContractAmt.writeUInt32LE(aggregateTx1.outputs[0].satoshis)
    let prevTx1ContractSPK = Buffer.concat([Buffer.from('22', 'hex'), scriptAggregatorP2TR.toBuffer()])
    let prevTx1HashData = aggregateHash1

    let ancestorTx0Ver = Buffer.alloc(4)
    ancestorTx0Ver.writeUInt32LE(ancestorTx0.version)
    let ancestorTx0Locktime = Buffer.alloc(4)
    ancestorTx0Locktime.writeUInt32LE(ancestorTx0.nLockTime)
    let ancestorTx0InputFee = new btc.encoding.BufferWriter()
    ancestorTx0.inputs[0].toBufferWriter(ancestorTx0InputFee);
    let ancestorTx0ContractAmt = Buffer.alloc(8)
    ancestorTx0ContractAmt.writeUInt32LE(ancestorTx0.outputs[0].satoshis)
    let ancestorTx0ContractSPK = Buffer.concat([Buffer.from('22', 'hex'), scriptAggregatorP2TR.toBuffer()])

    let ancestorTx1Ver = Buffer.alloc(4)
    ancestorTx1Ver.writeUInt32LE(ancestorTx1.version)
    let ancestorTx1Locktime = Buffer.alloc(4)
    ancestorTx1Locktime.writeUInt32LE(ancestorTx1.nLockTime)
    let ancestorTx1InputFee = new btc.encoding.BufferWriter()
    ancestorTx1.inputs[0].toBufferWriter(ancestorTx1InputFee);
    let ancestorTx1ContractAmt = Buffer.alloc(8)
    ancestorTx1ContractAmt.writeUInt32LE(ancestorTx1.outputs[0].satoshis)
    let ancestorTx1ContractSPK = Buffer.concat([Buffer.from('22', 'hex'), scriptAggregatorP2TR.toBuffer()])

    let ancestorTx2Ver = Buffer.alloc(4)
    ancestorTx2Ver.writeUInt32LE(ancestorTx2.version)
    let ancestorTx2Locktime = Buffer.alloc(4)
    ancestorTx2Locktime.writeUInt32LE(ancestorTx2.nLockTime)
    let ancestorTx2InputFee = new btc.encoding.BufferWriter()
    ancestorTx2.inputs[0].toBufferWriter(ancestorTx2InputFee);
    let ancestorTx2ContractAmt = Buffer.alloc(8)
    ancestorTx2ContractAmt.writeUInt32LE(ancestorTx2.outputs[0].satoshis)
    let ancestorTx2ContractSPK = Buffer.concat([Buffer.from('22', 'hex'), scriptAggregatorP2TR.toBuffer()])

    let ancestorTx3Ver = Buffer.alloc(4)
    ancestorTx3Ver.writeUInt32LE(ancestorTx3.version)
    let ancestorTx3Locktime = Buffer.alloc(4)
    ancestorTx3Locktime.writeUInt32LE(ancestorTx3.nLockTime)
    let ancestorTx3InputFee = new btc.encoding.BufferWriter()
    ancestorTx3.inputs[0].toBufferWriter(ancestorTx3InputFee);
    let ancestorTx3ContractAmt = Buffer.alloc(8)
    ancestorTx3ContractAmt.writeUInt32LE(ancestorTx3.outputs[0].satoshis)
    let ancestorTx3ContractSPK = Buffer.concat([Buffer.from('22', 'hex'), scriptAggregatorP2TR.toBuffer()])

    let fundingPrevout = new btc.encoding.BufferWriter()
    fundingPrevout.writeReverse(aggregateTx2.inputs[2].prevTxId);
    fundingPrevout.writeInt32LE(aggregateTx2.inputs[2].outputIndex);

    let prevTx0PrevH0 = aggregationData0.prevH0
    let prevTx0PrevH1 = aggregationData0.prevH1
    let prevTx0SumAmt = Buffer.alloc(2) // Bigint witnesses need to be minimally encoded! TODO: Do this automatically.
    prevTx0SumAmt.writeInt16LE(Number(aggregationData0.sumAmt))
    let prevTx1PrevH0 = aggregationData1.prevH0
    let prevTx1PrevH1 = aggregationData1.prevH1
    let prevTx1SumAmt = Buffer.alloc(2) // Bigint witnesses need to be minimally encoded! TODO: Do this automatically.
    prevTx1SumAmt.writeInt16LE(Number(aggregationData1.sumAmt))

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

        Buffer.from('', 'hex'), // is prev tx leaf (false)
        sigOperatorIn0,

        prevTx0Ver,
        prevTx0InputContract0.toBuffer(),
        prevTx0InputContract1.toBuffer(),
        prevTx0InputFee.toBuffer(),
        prevTx0ContractAmt,
        prevTx0ContractSPK,
        Buffer.from(prevTx0HashData, 'hex'),
        prevTx0Locktime,

        prevTx1Ver,
        prevTx1InputContract0.toBuffer(),
        prevTx1InputContract1.toBuffer(),
        prevTx1InputFee.toBuffer(),
        prevTx1ContractAmt,
        prevTx1ContractSPK,
        Buffer.from(prevTx1HashData, 'hex'),
        prevTx1Locktime,

        ancestorTx0Ver,
        Buffer.from('', 'hex'),
        Buffer.from('', 'hex'),
        ancestorTx0InputFee.toBuffer(),
        ancestorTx0ContractAmt,
        ancestorTx0ContractSPK,
        Buffer.from(ancestorTx0HashData, 'hex'),
        ancestorTx0Locktime,

        ancestorTx1Ver,
        Buffer.from('', 'hex'),
        Buffer.from('', 'hex'),
        ancestorTx1InputFee.toBuffer(),
        ancestorTx1ContractAmt,
        ancestorTx1ContractSPK,
        Buffer.from(ancestorTx1HashData, 'hex'),
        ancestorTx1Locktime,

        ancestorTx2Ver,
        Buffer.from('', 'hex'),
        Buffer.from('', 'hex'),
        ancestorTx2InputFee.toBuffer(),
        ancestorTx2ContractAmt,
        ancestorTx2ContractSPK,
        Buffer.from(ancestorTx2HashData, 'hex'),
        ancestorTx2Locktime,

        ancestorTx3Ver,
        Buffer.from('', 'hex'),
        Buffer.from('', 'hex'),
        ancestorTx3InputFee.toBuffer(),
        ancestorTx3ContractAmt,
        ancestorTx3ContractSPK,
        Buffer.from(ancestorTx3HashData, 'hex'),
        ancestorTx3Locktime,

        Buffer.from('01', 'hex'), // is ancestor leaf (true)

        Buffer.from(''),
        Buffer.from(''),
        Buffer.from(''),
        Buffer.from(''),
        Buffer.from(''),

        Buffer.from(''),
        Buffer.from(''),
        Buffer.from(''),
        Buffer.from(''),
        Buffer.from(''),

        fundingPrevout.toBuffer(),
        Buffer.from('01', 'hex'), // is first input (true)

        Buffer.from('', 'hex'),
        Buffer.from('', 'hex'),
        Buffer.from('', 'hex'),
        Buffer.from('', 'hex'),

        Buffer.from(prevTx0PrevH0, 'hex'),
        Buffer.from(prevTx0PrevH1, 'hex'),
        prevTx0SumAmt,
        Buffer.from(prevTx1PrevH0, 'hex'),
        Buffer.from(prevTx1PrevH1, 'hex'),
        prevTx1SumAmt,

        Buffer.from('', 'hex'), // OP_0 - first public method chosen

        scriptAggregator.toBuffer(),
        Buffer.from(cblockAggregator, 'hex')
    ]
    aggregateTx2.inputs[0].witnesses = witnessesIn0

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

        Buffer.from('', 'hex'), // is prev tx leaf (false)
        sigOperatorIn1,

        prevTx0Ver,
        prevTx0InputContract0.toBuffer(),
        prevTx0InputContract1.toBuffer(),
        prevTx0InputFee.toBuffer(),
        prevTx0ContractAmt,
        prevTx0ContractSPK,
        Buffer.from(prevTx0HashData, 'hex'),
        prevTx0Locktime,

        prevTx1Ver,
        prevTx1InputContract0.toBuffer(),
        prevTx1InputContract1.toBuffer(),
        prevTx1InputFee.toBuffer(),
        prevTx1ContractAmt,
        prevTx1ContractSPK,
        Buffer.from(prevTx1HashData, 'hex'),
        prevTx1Locktime,

        ancestorTx0Ver,
        Buffer.from('', 'hex'),
        Buffer.from('', 'hex'),
        ancestorTx0InputFee.toBuffer(),
        ancestorTx0ContractAmt,
        ancestorTx0ContractSPK,
        Buffer.from(ancestorTx0HashData, 'hex'),
        ancestorTx0Locktime,

        ancestorTx1Ver,
        Buffer.from('', 'hex'),
        Buffer.from('', 'hex'),
        ancestorTx1InputFee.toBuffer(),
        ancestorTx1ContractAmt,
        ancestorTx1ContractSPK,
        Buffer.from(ancestorTx1HashData, 'hex'),
        ancestorTx1Locktime,

        ancestorTx2Ver,
        Buffer.from('', 'hex'),
        Buffer.from('', 'hex'),
        ancestorTx2InputFee.toBuffer(),
        ancestorTx2ContractAmt,
        ancestorTx2ContractSPK,
        Buffer.from(ancestorTx2HashData, 'hex'),
        ancestorTx2Locktime,

        ancestorTx3Ver,
        Buffer.from('', 'hex'),
        Buffer.from('', 'hex'),
        ancestorTx3InputFee.toBuffer(),
        ancestorTx3ContractAmt,
        ancestorTx3ContractSPK,
        Buffer.from(ancestorTx3HashData, 'hex'),
        ancestorTx3Locktime,

        Buffer.from('01', 'hex'), // is ancestor leaf (true)

        Buffer.from(''),
        Buffer.from(''),
        Buffer.from(''),
        Buffer.from(''),
        Buffer.from(''),

        Buffer.from(''),
        Buffer.from(''),
        Buffer.from(''),
        Buffer.from(''),
        Buffer.from(''),

        fundingPrevout.toBuffer(),
        Buffer.from('', 'hex'), // is first input (false)

        Buffer.from('', 'hex'),
        Buffer.from('', 'hex'),
        Buffer.from('', 'hex'),
        Buffer.from('', 'hex'),

        Buffer.from(prevTx0PrevH0, 'hex'),
        Buffer.from(prevTx0PrevH1, 'hex'),
        prevTx0SumAmt,
        Buffer.from(prevTx1PrevH0, 'hex'),
        Buffer.from(prevTx1PrevH1, 'hex'),
        prevTx1SumAmt,

        Buffer.from('', 'hex'), // OP_0 - first public method chosen

        scriptAggregator.toBuffer(),
        Buffer.from(cblockAggregator, 'hex')
    ]
    aggregateTx2.inputs[1].witnesses = witnessesIn1

    return aggregateTx2
}

export async function performWithdrawalAggregation(
    utxos: UTXO[],
    withdrawalAmounts: bigint[],
    txFee: number,
    scriptAggregatorP2TR: btc.Script,
    cblockAggregator: string,
    scriptAggregator: btc.Script,
    tapleafAggregator: string,
    seckeyOperator: btc.PrivateKey
) {
    const txFunds = new btc.Transaction()
        .from(utxos)
        .to(myAddress, txFee)
        .to(myAddress, txFee)
        .to(myAddress, txFee)
        .to(myAddress, txFee)
        .to(myAddress, txFee)
        .to(myAddress, txFee)
        .to(myAddress, txFee)
        .to(myAddress, txFee)
        .change(myAddress)
        .feePerByte(2)
        .sign(myPrivateKey)

    utxos.length = 0
    utxos.push(
        {
            address: myAddress.toString(),
            txId: txFunds.id,
            outputIndex: txFunds.outputs.length - 1,
            script: new btc.Script(myAddress),
            satoshis: txFunds.outputs[txFunds.outputs.length - 1].satoshis
        }
    )

    ////////////////////////////////////////////////////////////////////
    //////// Construct 4x leaf withdrawal request transactions. ////////
    ////////////////////////////////////////////////////////////////////
    const myAddr = toByteString(myAddress.hashBuffer.toString('hex')) as Addr
    const withdrawalDataList: WithdrawalData[] = [
        {
            address: myAddr,
            amount: withdrawalAmounts[0]
        },
        {
            address: myAddr,
            amount: withdrawalAmounts[1]
        },
        {
            address: myAddr,
            amount: withdrawalAmounts[2]
        },
        {
            address: myAddr,
            amount: withdrawalAmounts[3]
        },
    ]
    const withdrawalDataHashList: Sha256[] = []
    for (const withdrawalData of withdrawalDataList) {
        withdrawalDataHashList.push(WithdrawalAggregator.hashWithdrawalData(withdrawalData))
    }

    let fundingUTXOs: UTXO[] = []
    for (let i = 0; i < 4; i++) {
        fundingUTXOs.push({
            address: myAddress.toString(),
            txId: txFunds.id,
            outputIndex: i,
            script: new btc.Script(myAddress),
            satoshis: txFunds.outputs[i].satoshis
        })
    }

    const { ownProofTxns, leafTxns } = createLeafWithdrawalTxns(
        4, withdrawalDataList, fundingUTXOs, scriptAggregatorP2TR
    )

    //////////////////////////////////////////
    //////// Merge leaf 0 and leaf 1. ////////
    //////////////////////////////////////////
    let fundingUTXO = {
        address: myAddress.toString(),
        txId: txFunds.id,
        outputIndex: 4,
        script: new btc.Script(myAddress),
        satoshis: txFunds.outputs[4].satoshis
    }

    const aggregateTx0 = await mergeWithdrawalLeaves(
        leafTxns[0], leafTxns[1], ownProofTxns[0], ownProofTxns[1],
        fundingUTXO, withdrawalDataList[0], withdrawalDataList[1],
        withdrawalDataHashList[0], withdrawalDataHashList[1],
        scriptAggregatorP2TR, tapleafAggregator, scriptAggregator, cblockAggregator, seckeyOperator
    )

    //////////////////////////////////////////
    //////// Merge leaf 2 and leaf 3. ////////
    //////////////////////////////////////////
    fundingUTXO = {
        address: myAddress.toString(),
        txId: txFunds.id,
        outputIndex: 5,
        script: new btc.Script(myAddress),
        satoshis: txFunds.outputs[5].satoshis
    }

    const aggregateTx1 = await mergeWithdrawalLeaves(
        leafTxns[2], leafTxns[3], ownProofTxns[2], ownProofTxns[3],
        fundingUTXO, withdrawalDataList[2], withdrawalDataList[3],
        withdrawalDataHashList[2], withdrawalDataHashList[3],
        scriptAggregatorP2TR, tapleafAggregator, scriptAggregator, cblockAggregator, seckeyOperator
    )

    ////////////////////////////////////////////
    //////// Merge two aggregate nodes. ////////
    ////////////////////////////////////////////
    fundingUTXO = {
        address: myAddress.toString(),
        txId: txFunds.id,
        outputIndex: 6,
        script: new btc.Script(myAddress),
        satoshis: txFunds.outputs[6].satoshis
    }

    let aggregationData0: AggregationData = {
        prevH0: withdrawalDataHashList[0],
        prevH1: withdrawalDataHashList[1],
        sumAmt: withdrawalAmounts[0] + withdrawalAmounts[1]
    }

    let aggregationData1: AggregationData = {
        prevH0: withdrawalDataHashList[2],
        prevH1: withdrawalDataHashList[3],
        sumAmt: withdrawalAmounts[2] + withdrawalAmounts[3]
    }

    const aggregateTx2 = await mergeAggregateWithdrawalNodes(
        aggregateTx0, aggregateTx1, leafTxns[0], leafTxns[1], leafTxns[2], leafTxns[3],
        aggregationData0, aggregationData1,
        withdrawalDataHashList[0], withdrawalDataHashList[1], withdrawalDataHashList[2], withdrawalDataHashList[3],
        fundingUTXO, scriptAggregatorP2TR, tapleafAggregator, scriptAggregator, cblockAggregator, seckeyOperator
    )

    const intermediateSums = getIntermediateSums(withdrawalDataList)
    const withdrawalTree = initWithdrawalTree(
        withdrawalDataList, intermediateSums
    )
    
    return {
        withdrawalDataList,
        withdrawalDataHashList,
        withdrawalTree,
        intermediateSums,
        txFunds,
        leafTxns,
        aggregateTx0,
        aggregateTx1,
        aggregateTx2
    }

}

describe('Test SmartContract `WithdrawalAggregator`', () => {
    let seckeyOperator
    let pubkeyOperator
    let addrP2WPKHOperator

    before(async () => {
        seckeyOperator = myPrivateKey
        pubkeyOperator = myPublicKey
        addrP2WPKHOperator = myAddress

        await WithdrawalAggregator.loadArtifact()
        await Bridge.loadArtifact()
    })

    it('should pass', async () => {
        // Create Bridge instance to get SPK which is used in WithrawalAggregators constructor.
        const bridge = new Bridge(
            PubKey(toByteString(pubkeyOperator.toString())),
            toByteString('')
        )
        const scriptBridge = bridge.lockingScript
        const tapleafBridge = Tap.encodeScript(scriptBridge.toBuffer())

        const [tpubkeyBridge, cblockBridge] = Tap.getPubKey(DISABLE_KEYSPEND_PUBKEY, { target: tapleafBridge })
        const scriptBridgeP2TR = new btc.Script(`OP_1 32 0x${tpubkeyBridge}}`)

        // Create aggregator instance to get P2TR address and other relevant info.
        const aggregator = new WithdrawalAggregator(
            PubKey(toByteString(pubkeyOperator.toString())),
            toByteString(scriptBridgeP2TR.toBuffer().toString('hex'))
        )

        const scriptAggregator = aggregator.lockingScript
        const tapleafAggregator = Tap.encodeScript(scriptAggregator.toBuffer())

        const [tpubkeyAggregator, cblockAggregator] = Tap.getPubKey(DISABLE_KEYSPEND_PUBKEY, { target: tapleafAggregator })
        const scriptAggregatorP2TR = new btc.Script(`OP_1 32 0x${tpubkeyAggregator}}`)

        // Create transactions used to fund our test txns.
        let utxos = await fetchP2WPKHUtxos(myAddress)
        if (utxos.length === 0) {
            throw new Error(`No UTXO's for address: ${myAddress.toString()}`)
        }

        const withdrawalAmounts = [1000n, 800n, 700n, 998n]
        const txFee = 3000

        const aggregationRes = await performWithdrawalAggregation(
            utxos, withdrawalAmounts, txFee, scriptAggregatorP2TR, cblockAggregator,
            scriptAggregator, tapleafAggregator, seckeyOperator
        )

        // Run locally
        let interpreter = new btc.Script.Interpreter()
        let flags = btc.Script.Interpreter.SCRIPT_VERIFY_WITNESS | btc.Script.Interpreter.SCRIPT_VERIFY_TAPROOT | btc.Script.Interpreter.SCRIPT_VERIFY_DISCOURAGE_OP_SUCCESS

        let res = interpreter.verify(new btc.Script(''), aggregationRes.leafTxns[0].outputs[0].script, aggregationRes.aggregateTx0, 0, flags, aggregationRes.aggregateTx0.inputs[0].witnesses, aggregationRes.leafTxns[0].outputs[0].satoshis)
        expect(res).to.be.true
        res = interpreter.verify(new btc.Script(''), aggregationRes.leafTxns[1].outputs[0].script, aggregationRes.aggregateTx0, 1, flags, aggregationRes.aggregateTx0.inputs[1].witnesses, aggregationRes.leafTxns[1].outputs[0].satoshis)
        expect(res).to.be.true
        res = interpreter.verify(new btc.Script(''), aggregationRes.leafTxns[2].outputs[0].script, aggregationRes.aggregateTx1, 0, flags, aggregationRes.aggregateTx1.inputs[0].witnesses, aggregationRes.leafTxns[2].outputs[0].satoshis)
        expect(res).to.be.true
        res = interpreter.verify(new btc.Script(''), aggregationRes.leafTxns[3].outputs[0].script, aggregationRes.aggregateTx1, 1, flags, aggregationRes.aggregateTx1.inputs[1].witnesses, aggregationRes.leafTxns[3].outputs[0].satoshis)
        expect(res).to.be.true
        res = interpreter.verify(new btc.Script(''), aggregationRes.aggregateTx0.outputs[0].script, aggregationRes.aggregateTx2, 0, flags, aggregationRes.aggregateTx2.inputs[0].witnesses, aggregationRes.aggregateTx0.outputs[0].satoshis)
        expect(res).to.be.true
        res = interpreter.verify(new btc.Script(''), aggregationRes.aggregateTx1.outputs[0].script, aggregationRes.aggregateTx2, 1, flags, aggregationRes.aggregateTx2.inputs[1].witnesses, aggregationRes.aggregateTx1.outputs[0].satoshis)
        expect(res).to.be.true
    })

})