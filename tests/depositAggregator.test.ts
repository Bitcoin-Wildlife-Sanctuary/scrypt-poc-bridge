// @ts-ignore
import btc = require('bitcore-lib-inquisition');
import { Tap } from '@cmdcode/tapscript'  // Requires node >= 19

import * as dotenv from 'dotenv';
dotenv.config();

import { expect, use } from 'chai'
import chaiAsPromised from 'chai-as-promised'
use(chaiAsPromised)

import { DepositAggregator, DepositData } from '../src/contracts/depositAggregator'
import { Bridge } from '../src/contracts/bridge'
import { hash256, PubKey, Sha256, toByteString, UTXO } from 'scrypt-ts';
import { DISABLE_KEYSPEND_PUBKEY, fetchP2WPKHUtxos, schnorrTrick } from './utils/txHelper';
import { myAddress, myPrivateKey, myPublicKey } from './utils/privateKey';


export function createLeafDepositTxns(
    nDeposits: number,
    deposits: DepositData[],
    fundingUTXOS: UTXO[],
    scriptAggregatorP2TR: btc.Script
): btc.Transaction[] {
    const leafTxns: btc.Transaction[] = []

    for (let i = 0; i < nDeposits; i++) {
        // UTXO where our leaf tx gets the needed funds from.
        const fundingUTXO = fundingUTXOS[i]

        // Deposit information.
        const depositData = deposits[i]
        const depositDataHash = DepositAggregator.hashDepositData(depositData)
        const opRetScript = new btc.Script(`6a20${depositDataHash}`)

        // Construct leaf txn.
        const leafTx = new btc.Transaction()
            .from(fundingUTXO)
            .addOutput(new btc.Transaction.Output({
                satoshis: Number(depositData.amount),
                script: scriptAggregatorP2TR
            }))
            .addOutput(new btc.Transaction.Output({
                satoshis: 0,
                script: opRetScript
            }))
            .sign(myPrivateKey)

        leafTxns.push(leafTx)
    }

    return leafTxns
}

export async function mergeDepositLeaves(
    leafTx0: btc.Transaction,
    leafTx1: btc.Transaction,
    fundingUTXO: UTXO,
    depositData0: DepositData,
    depositData1: DepositData,
    depositDataHash0: Sha256,
    depositDataHash1: Sha256,
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

    const aggregateHash0 = hash256(depositDataHash0 + depositDataHash1)
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
            satoshis: Number(
                depositData0.amount + depositData1.amount
            ),
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
    let prevTx0HashData = depositDataHash0

    let prevTx1Ver = Buffer.alloc(4)
    prevTx1Ver.writeUInt32LE(leafTx1.version)
    let prevTx1Locktime = Buffer.alloc(4)
    prevTx1Locktime.writeUInt32LE(leafTx1.nLockTime)
    let prevTx1InputFee = new btc.encoding.BufferWriter()
    leafTx1.inputs[0].toBufferWriter(prevTx1InputFee);
    let prevTx1ContractAmt = Buffer.alloc(8)
    prevTx1ContractAmt.writeUInt32LE(leafTx1.outputs[0].satoshis)
    let prevTx1ContractSPK = Buffer.concat([Buffer.from('22', 'hex'), scriptAggregatorP2TR.toBuffer()])
    let prevTx1HashData = depositDataHash1

    let fundingPrevout = new btc.encoding.BufferWriter()
    fundingPrevout.writeReverse(aggregateTx.inputs[2].prevTxId);
    fundingPrevout.writeInt32LE(aggregateTx.inputs[2].outputIndex);

    let depositData0AddressBuff = Buffer.from(depositData0.address, 'hex')
    let depositData0AmtBuff = Buffer.alloc(2) // Bigint witnesses need to be minimally encoded! TODO: Do this automatically.
    depositData0AmtBuff.writeInt16LE(Number(depositData0.amount))

    let depositData1AddressBuff = Buffer.from(depositData1.address, 'hex')
    let depositData1AmtBuff = Buffer.alloc(2)
    depositData1AmtBuff.writeInt16LE(Number(depositData1.amount))

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

        fundingPrevout.toBuffer(),
        Buffer.from('01', 'hex'), // is first input (true)

        depositData0AddressBuff,
        depositData0AmtBuff,
        depositData1AddressBuff,
        depositData1AmtBuff,

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

        fundingPrevout.toBuffer(),
        Buffer.from('', 'hex'), // is first input (false)

        depositData0AddressBuff,
        depositData0AmtBuff,
        depositData1AddressBuff,
        depositData1AmtBuff,

        Buffer.from('', 'hex'), // OP_0 - first public method chosen

        scriptAggregator.toBuffer(),
        Buffer.from(cblockAggregator, 'hex')
    ]
    aggregateTx.inputs[1].witnesses = witnessesIn1


    return aggregateTx
}

export async function mergeAggregateDepositNodes(
    aggregateTx0: btc.Transaction,
    aggregateTx1: btc.Transaction,
    ancestorTx0: btc.Transaction,
    ancestorTx1: btc.Transaction,
    ancestorTx2: btc.Transaction,
    ancestorTx3: btc.Transaction,
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

    const aggregateHash0 = hash256(ancestorTx0HashData + ancestorTx1HashData)
    const aggregateHash1 = hash256(ancestorTx2HashData + ancestorTx3HashData)
    const aggregateHashNew = hash256(aggregateHash0 + aggregateHash1)
    let opRetScript = new btc.Script(`6a20${aggregateHashNew}`)

    const aggregateTx = new btc.Transaction()
        .from(
            [
                aggregateTx0UTXO,
                aggregateTx1UTXO,
                fundingUTXO
            ]
        )
        .addOutput(new btc.Transaction.Output({
            satoshis: aggregateTx0UTXO.satoshis + aggregateTx1UTXO.satoshis,
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
    fundingPrevout.writeReverse(aggregateTx.inputs[2].prevTxId);
    fundingPrevout.writeInt32LE(aggregateTx.inputs[2].outputIndex);

    let depositData0AmtBuff = Buffer.alloc(2) // Bigint witnesses need to be minimally encoded! TODO: Do this automatically.
    depositData0AmtBuff.writeInt16LE(aggregateTx0.outputs[0].satoshis)
    let depositData1AmtBuff = Buffer.alloc(2)
    depositData1AmtBuff.writeInt16LE(aggregateTx1.outputs[0].satoshis)

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

        fundingPrevout.toBuffer(),
        Buffer.from('01', 'hex'), // is first input (true)

        Buffer.from(''),
        depositData0AmtBuff,
        Buffer.from(''),
        depositData1AmtBuff,

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

        fundingPrevout.toBuffer(),
        Buffer.from('', 'hex'), // is first input (false)

        Buffer.from(''),
        depositData0AmtBuff,
        Buffer.from(''),
        depositData1AmtBuff,

        Buffer.from('', 'hex'), // OP_0 - first public method chosen

        scriptAggregator.toBuffer(),
        Buffer.from(cblockAggregator, 'hex')
    ]
    aggregateTx.inputs[1].witnesses = witnessesIn1

    return aggregateTx
}

export async function performValidDepositAggregation(
    utxos: UTXO[],
    depositAmounts: bigint[],
    txFee: number,
    scriptAggregatorP2TR: btc.Script,
    cblockAggregator: string,
    scriptAggregator: btc.Script,
    tapleafAggregator: string,
    seckeyOperator: btc.PrivateKey
) {
    const txFunds = new btc.Transaction()
        .from(utxos)
        .to(myAddress, Number(depositAmounts[0]) + txFee)
        .to(myAddress, Number(depositAmounts[1]) + txFee)
        .to(myAddress, Number(depositAmounts[2]) + txFee)
        .to(myAddress, Number(depositAmounts[3]) + txFee)
        .to(myAddress, txFee)
        .to(myAddress, txFee)
        .to(myAddress, txFee)
        .to(myAddress, txFee)
        .change(myAddress)
        .feePerByte(2)
        .sign(myPrivateKey)


    /////////////////////////////////////////////////////////
    //////// Construct 4x leaf deposit transactions. ////////
    /////////////////////////////////////////////////////////
    const myAddr = toByteString(myAddress.toBuffer().toString('hex')) as Sha256
    const depositDataList: DepositData[] = [
        {
            address: myAddr,
            amount: depositAmounts[0]
        },
        {
            address: myAddr,
            amount: depositAmounts[1]
        },
        {
            address: myAddr,
            amount: depositAmounts[2]
        },
        {
            address: myAddr,
            amount: depositAmounts[3]
        },
    ]
    const depositDataHashList: Sha256[] = []
    for (const depositData of depositDataList) {
        depositDataHashList.push(DepositAggregator.hashDepositData(depositData))
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

    const leafTxns: btc.Transaction[] = createLeafDepositTxns(
        4, depositDataList, fundingUTXOs, scriptAggregatorP2TR
    )

    //////////////////////////////////////////
    //////// Merge leaf 0 and leaf 1. ////////
    //////////////////////////////////////////
    let fundingUTXO = {
        address: myAddress.toString(),
        txId: txFunds.id,
        outputIndex: 5,
        script: new btc.Script(myAddress),
        satoshis: txFunds.outputs[5].satoshis
    }

    const aggregateTx0 = await mergeDepositLeaves(
        leafTxns[0], leafTxns[1], fundingUTXO,
        depositDataList[0], depositDataList[1], depositDataHashList[0], depositDataHashList[1],
        scriptAggregatorP2TR, tapleafAggregator, scriptAggregator, cblockAggregator, seckeyOperator
    )

    //////////////////////////////////////////
    //////// Merge leaf 2 and leaf 3. ////////
    //////////////////////////////////////////
    fundingUTXO = {
        address: myAddress.toString(),
        txId: txFunds.id,
        outputIndex: 6,
        script: new btc.Script(myAddress),
        satoshis: txFunds.outputs[6].satoshis
    }

    const aggregateTx1 = await mergeDepositLeaves(
        leafTxns[2], leafTxns[3], fundingUTXO,
        depositDataList[2], depositDataList[3], depositDataHashList[2], depositDataHashList[3],
        scriptAggregatorP2TR, tapleafAggregator, scriptAggregator, cblockAggregator, seckeyOperator
    )

    ////////////////////////////////////////////
    //////// Merge two aggregate nodes. ////////
    ////////////////////////////////////////////
    fundingUTXO = {
        address: myAddress.toString(),
        txId: txFunds.id,
        outputIndex: 7,
        script: new btc.Script(myAddress),
        satoshis: txFunds.outputs[7].satoshis
    }

    const aggregateTx2 = await mergeAggregateDepositNodes(
        aggregateTx0, aggregateTx1, leafTxns[0], leafTxns[1], leafTxns[2], leafTxns[3],
        depositDataHashList[0], depositDataHashList[1], depositDataHashList[2], depositDataHashList[3],
        fundingUTXO, scriptAggregatorP2TR, tapleafAggregator, scriptAggregator, cblockAggregator, seckeyOperator
    )

    return {
        txFunds,
        leafTxns,
        aggregateTx0,
        aggregateTx1,
        aggregateTx2
    }
}


describe('Test SmartContract `DepositAggregator`', () => {
    let seckeyOperator
    let pubkeyOperator

    before(async () => {
        seckeyOperator = myPrivateKey
        pubkeyOperator = myPublicKey

        await DepositAggregator.loadArtifact()
        await Bridge.loadArtifact()
    })

    it('should pass', async () => {
        // Create Bridge instance to get SPK which is used in DepositAggregators constructor.
        const bridge = new Bridge(
            PubKey(toByteString(pubkeyOperator.toString())),
            toByteString('')
        )

        const scriptBridge = bridge.lockingScript
        const tapleafBridge = Tap.encodeScript(scriptBridge.toBuffer())

        const [tpubkeyBridge, cblockBridge] = Tap.getPubKey(DISABLE_KEYSPEND_PUBKEY, { target: tapleafBridge })
        const scriptBridgeP2TR = new btc.Script(`OP_1 32 0x${tpubkeyBridge}}`)

        // Create aggregator instance to get P2TR address and other relevant info.
        const aggregator = new DepositAggregator(
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

        const depositAmounts = [1329n, 1400n, 1500n, 1888n]
        const txFee = 3000


        const aggregationRes = await performValidDepositAggregation(
            utxos, depositAmounts, txFee, scriptAggregatorP2TR, cblockAggregator,
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