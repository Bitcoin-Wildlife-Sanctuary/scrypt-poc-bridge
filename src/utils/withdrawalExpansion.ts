// @ts-ignore
import btc = require('bitcore-lib-inquisition');
import { ByteString, UTXO } from "scrypt-ts"
import { AccountData } from "../contracts/bridge"
import { WithdrawalData } from "../contracts/withdrawalAggregator"
import { myAddress as operatorAddress, myPrivateKey as operatorPrivateKey } from "../utils/privateKey"
import { hexLEtoDecimal, schnorrTrick } from "../utils/txHelper"
import { MerkleTree } from '../utils/merkleTree';


export async function performWithdrawalExpansion(
    operatorUTXOs: UTXO[],
    accountsTree: MerkleTree,
    bridgeTx: btc.Transaction,
    intermediateSums: ByteString[][],
    withdrawalDataList: WithdrawalData[],
    withdrawalTree: MerkleTree,
    txFee: number,
    
    expanderRoot: string,
    expanderAmt: bigint,

    scriptBridgeP2TR: btc.Script,
    scriptDepositAggregatorP2TR: btc.Script,
    scriptWithdrawalAggregatorP2TR: btc.Script,

    scriptExpanderP2TR: btc.Script,
    scriptExpander: btc.Script,
    tapleafExpander: string,
    cblockExpander: string
) {
    let expanderRootUTXO: UTXO = {
        txId: bridgeTx.id,
        outputIndex: 2,
        script: scriptExpanderP2TR,
        satoshis: bridgeTx.outputs[2].satoshis
    }

    const txFunds = new btc.Transaction()
        .from(operatorUTXOs)
        .to(operatorAddress, txFee)
        .to(operatorAddress, txFee)
        .to(operatorAddress, txFee)
        .to(operatorAddress, txFee)
        .to(operatorAddress, txFee)
        .to(operatorAddress, txFee)
        .change(operatorAddress)
        .feePerByte(2)
        .sign(operatorPrivateKey)

    operatorUTXOs.length = 0
    operatorUTXOs.push(
        {
            address: operatorAddress.toString(),
            txId: txFunds.id,
            outputIndex: txFunds.outputs.length - 1,
            script: new btc.Script(operatorAddress),
            satoshis: txFunds.outputs[txFunds.outputs.length - 1].satoshis
        }
    )


    let fundingUTXO = {
        address: operatorAddress.toString(),
        txId: txFunds.id,
        outputIndex: 0,
        script: new btc.Script(operatorAddress),
        satoshis: txFunds.outputs[0].satoshis
    }

    let splitAmt0 = hexLEtoDecimal(intermediateSums[0][0])
    let splitAmt1 = hexLEtoDecimal(intermediateSums[0][1])

    let aggregationHash = withdrawalTree.levels[2][0]

    let opRetScript = new btc.Script(`6a20${aggregationHash}`)

    const expanderTx0 = new btc.Transaction()
        .from(
            [
                expanderRootUTXO,
                fundingUTXO
            ]
        )
        .addOutput(new btc.Transaction.Output({
            satoshis: splitAmt0,
            script: scriptExpanderP2TR
        }))
        .addOutput(new btc.Transaction.Output({
            satoshis: splitAmt1,
            script: scriptExpanderP2TR
        }))
        .addOutput(new btc.Transaction.Output({
            satoshis: 0,
            script: opRetScript
        }))
        .sign(operatorPrivateKey)

    let schnorrTrickData = await schnorrTrick(expanderTx0, tapleafExpander, 0)
    let sigOperator = btc.crypto.Schnorr.sign(operatorPrivateKey, schnorrTrickData.sighash.hash);

    let isExpandingPrevTxFirstOutput = Buffer.from('', 'hex')
    let isPrevTxBridge = Buffer.from('01', 'hex')

    let prevTxBridgeVer = Buffer.alloc(4)
    prevTxBridgeVer.writeUInt32LE(bridgeTx.version)
    let prevTxBridgeLocktime = Buffer.alloc(4)
    prevTxBridgeLocktime.writeUInt32LE(bridgeTx.nLockTime)
    let prevTxBridgeInputsBW = new btc.encoding.BufferWriter()
    prevTxBridgeInputsBW.writeUInt8(bridgeTx.inputs.length)
    for (const input of bridgeTx.inputs) {
        input.toBufferWriter(prevTxBridgeInputsBW);
    }
    let prevTxBridgeInputs = prevTxBridgeInputsBW.toBuffer()
    let prevTxBridgeContractAmt = Buffer.alloc(2) // Bigint witnesses need to be minimally encoded! TODO: Do this automatically.
    prevTxBridgeContractAmt.writeInt16LE(bridgeTx.outputs[0].satoshis)
    let prevTxBridgeContractSPK = Buffer.concat([Buffer.from('22', 'hex'), scriptBridgeP2TR.toBuffer()])
    let prevTxBridgeExpanderSPK = Buffer.concat([Buffer.from('22', 'hex'), scriptExpanderP2TR.toBuffer()])
    let prevTxBridgeAccountsRoot = Buffer.from(accountsTree.getRoot(), 'hex')
    let prevTxBridgeExpanderRoot = Buffer.from(expanderRoot, 'hex')
    let prevTxBridgeExpanderAmt = Buffer.alloc(2) // Bigint witnesses need to be minimally encoded! TODO: Do this automatically.
    prevTxBridgeExpanderAmt.writeInt16LE(Number(expanderAmt))
    let prevTxBridgeDepositAggregatorSPK = Buffer.concat([Buffer.from('22', 'hex'), scriptDepositAggregatorP2TR.toBuffer()])
    let prevTxBridgeWithdrawalAggregatorSPK = Buffer.concat([Buffer.from('22', 'hex'), scriptWithdrawalAggregatorP2TR.toBuffer()])

    let prevTxExpanderVer = Buffer.from('', 'hex')
    let prevTxExpanderInputContract = Buffer.from('', 'hex')
    let prevTxExpanderInputFee = Buffer.from('', 'hex')
    let prevTxExpanderContractSPK = Buffer.from('', 'hex')
    let prevTxExpanderOutput0Amt = Buffer.from('', 'hex')
    let prevTxExpanderOutput1Amt = Buffer.from('', 'hex')
    let prevTxExpanderHashData = Buffer.from('', 'hex')
    let prevTxExpanderLocktime = Buffer.from('', 'hex')

    let prevAggregationDataPrevH0 = Buffer.from(withdrawalTree.levels[1][0], 'hex')
    let prevAggregationDataPrevH1 = Buffer.from(withdrawalTree.levels[1][1], 'hex')
    let prevAggregationDataSumAmt = Buffer.alloc(2) // Bigint witnesses need to be minimally encoded! TODO: Do this automatically.
    prevAggregationDataSumAmt.writeInt16LE(Number(expanderAmt))

    let currentAggregationDataPrevH0 = Buffer.from(withdrawalTree.levels[1][0], 'hex')
    let currentAggregationDataPrevH1 = Buffer.from(withdrawalTree.levels[1][1], 'hex')
    let currentAggregationDataSumAmt = Buffer.alloc(2) // Bigint witnesses need to be minimally encoded! TODO: Do this automatically.
    currentAggregationDataSumAmt.writeInt16LE(Number(expanderAmt))

    let nextAggregationData0PrevH0 = Buffer.from(withdrawalTree.levels[0][0], 'hex')
    let nextAggregationData0PrevH1 = Buffer.from(withdrawalTree.levels[0][1], 'hex')
    let nextAggregationData0SumAmt = Buffer.alloc(2) // Bigint witnesses need to be minimally encoded! TODO: Do this automatically.
    nextAggregationData0SumAmt.writeInt16LE(splitAmt0)

    let nextAggregationData1PrevH0 = Buffer.from(withdrawalTree.levels[0][2], 'hex')
    let nextAggregationData1PrevH1 = Buffer.from(withdrawalTree.levels[0][3], 'hex')
    let nextAggregationData1SumAmt = Buffer.alloc(2) // Bigint witnesses need to be minimally encoded! TODO: Do this automatically.
    nextAggregationData1SumAmt.writeInt16LE(splitAmt1)

    let isExpandingLeaves = Buffer.from('', 'hex')

    let withdrawalData0AddressBuff = Buffer.from('', 'hex')
    let withdrawalData0AmtBuff = Buffer.alloc(2) // Bigint witnesses need to be minimally encoded! TODO: Do this automatically.
    withdrawalData0AmtBuff.writeInt16LE(0)

    let withdrawalData1AddressBuff = Buffer.from('', 'hex')
    let withdrawalData1AmtBuff = Buffer.alloc(2) // Bigint witnesses need to be minimally encoded! TODO: Do this automatically.
    withdrawalData1AmtBuff.writeInt16LE(0)

    let isLastAggregationLevel = Buffer.from('', 'hex')

    let fundingPrevoutBW = new btc.encoding.BufferWriter()
    fundingPrevoutBW.writeReverse(expanderTx0.inputs[1].prevTxId);
    fundingPrevoutBW.writeInt32LE(expanderTx0.inputs[1].outputIndex);
    let fundingPrevout = fundingPrevoutBW.toBuffer()

    let witnesses = [
        schnorrTrickData.preimageParts.txVersion,
        schnorrTrickData.preimageParts.nLockTime,
        schnorrTrickData.preimageParts.hashPrevouts,
        schnorrTrickData.preimageParts.hashSpentAmounts,
        schnorrTrickData.preimageParts.hashScripts,
        schnorrTrickData.preimageParts.hashSequences,
        schnorrTrickData.preimageParts.hashOutputs,
        schnorrTrickData.preimageParts.spendType,
        schnorrTrickData.preimageParts.inputNumber,
        schnorrTrickData.preimageParts.tapleafHash,
        schnorrTrickData.preimageParts.keyVersion,
        schnorrTrickData.preimageParts.codeseparatorPosition,
        schnorrTrickData.sighash.hash,
        schnorrTrickData._e,
        Buffer.from([schnorrTrickData.eLastByte]),

        sigOperator,

        isExpandingPrevTxFirstOutput,
        isPrevTxBridge,

        prevTxBridgeVer,
        prevTxBridgeInputs,
        prevTxBridgeContractSPK,
        prevTxBridgeExpanderSPK,
        prevTxBridgeContractAmt,
        prevTxBridgeAccountsRoot,
        prevTxBridgeExpanderRoot,
        prevTxBridgeExpanderAmt,
        prevTxBridgeDepositAggregatorSPK,
        prevTxBridgeWithdrawalAggregatorSPK,
        prevTxBridgeLocktime,

        prevTxExpanderVer,
        prevTxExpanderInputContract,
        prevTxExpanderInputFee,
        prevTxExpanderContractSPK,
        prevTxExpanderOutput0Amt,
        prevTxExpanderOutput1Amt,
        prevTxExpanderHashData,
        prevTxExpanderLocktime,

        prevAggregationDataPrevH0,
        prevAggregationDataPrevH1,
        prevAggregationDataSumAmt,

        currentAggregationDataPrevH0,
        currentAggregationDataPrevH1,
        currentAggregationDataSumAmt,

        nextAggregationData0PrevH0,
        nextAggregationData0PrevH1,
        nextAggregationData0SumAmt,

        nextAggregationData1PrevH0,
        nextAggregationData1PrevH1,
        nextAggregationData1SumAmt,

        isExpandingLeaves,

        withdrawalData0AddressBuff,
        withdrawalData0AmtBuff,

        withdrawalData1AddressBuff,
        withdrawalData1AmtBuff,

        isLastAggregationLevel,

        fundingPrevout,

        scriptExpander.toBuffer(),
        Buffer.from(cblockExpander, 'hex')
    ]

    expanderTx0.inputs[0].witnesses = witnesses

    ////////////////////////////////
    // Expansion of first branch. //
    ////////////////////////////////
    let expanderUTXO = {
        txId: expanderTx0.id,
        outputIndex: 0,
        script: scriptExpanderP2TR,
        satoshis: expanderTx0.outputs[0].satoshis
    }
    fundingUTXO = {
        address: operatorAddress.toString(),
        txId: txFunds.id,
        outputIndex: 0,
        script: new btc.Script(operatorAddress),
        satoshis: txFunds.outputs[0].satoshis
    }

    splitAmt0 = Number(withdrawalDataList[0].amount)
    splitAmt1 = Number(withdrawalDataList[1].amount)

    aggregationHash = withdrawalTree.levels[1][0]

    opRetScript = new btc.Script(`6a20${aggregationHash}`)

    const expanderTx1 = new btc.Transaction()
        .from(
            [
                expanderUTXO,
                fundingUTXO
            ]
        )
        .addOutput(new btc.Transaction.Output({
            satoshis: splitAmt0,
            script: scriptExpanderP2TR
        }))
        .addOutput(new btc.Transaction.Output({
            satoshis: splitAmt1,
            script: scriptExpanderP2TR
        }))
        .addOutput(new btc.Transaction.Output({
            satoshis: 0,
            script: opRetScript
        }))
        .sign(operatorPrivateKey)

    schnorrTrickData = await schnorrTrick(expanderTx1, tapleafExpander, 0)
    sigOperator = btc.crypto.Schnorr.sign(operatorPrivateKey, schnorrTrickData.sighash.hash);

    isExpandingPrevTxFirstOutput = Buffer.from('01', 'hex')
    isPrevTxBridge = Buffer.from('', 'hex')

    prevTxBridgeVer = Buffer.from('', 'hex')
    prevTxBridgeLocktime = Buffer.from('', 'hex')
    prevTxBridgeInputs = Buffer.from('', 'hex')
    prevTxBridgeContractAmt = Buffer.from('', 'hex')
    prevTxBridgeContractSPK = Buffer.from('', 'hex')
    prevTxBridgeExpanderSPK = Buffer.from('', 'hex')
    prevTxBridgeAccountsRoot = Buffer.from('', 'hex')
    prevTxBridgeExpanderRoot = Buffer.from('', 'hex')
    prevTxBridgeExpanderAmt = Buffer.from('', 'hex')
    prevTxBridgeDepositAggregatorSPK = Buffer.from('', 'hex')
    prevTxBridgeWithdrawalAggregatorSPK = Buffer.from('', 'hex')

    prevTxExpanderVer = Buffer.alloc(4)
    prevTxExpanderVer.writeUInt32LE(expanderTx0.version)
    let prevTxExpanderInputContractBW = new btc.encoding.BufferWriter()
    expanderTx0.inputs[0].toBufferWriter(prevTxExpanderInputContractBW);
    prevTxExpanderInputContract = prevTxExpanderInputContractBW.toBuffer()
    let prevTxExpanderInputFeeBW = new btc.encoding.BufferWriter()
    expanderTx0.inputs[1].toBufferWriter(prevTxExpanderInputFeeBW);
    prevTxExpanderInputFee = prevTxExpanderInputFeeBW.toBuffer()
    prevTxExpanderContractSPK = Buffer.concat([Buffer.from('22', 'hex'), scriptExpanderP2TR.toBuffer()])
    prevTxExpanderOutput0Amt = Buffer.alloc(2) // Bigint witnesses need to be minimally encoded! TODO: Do this automatically.
    prevTxExpanderOutput0Amt.writeInt16LE(expanderTx0.outputs[0].satoshis)
    prevTxExpanderOutput1Amt = Buffer.alloc(2) // Bigint witnesses need to be minimally encoded! TODO: Do this automatically.
    prevTxExpanderOutput1Amt.writeInt16LE(expanderTx0.outputs[1].satoshis)
    prevTxExpanderHashData = Buffer.from(expanderRoot, 'hex')
    prevTxExpanderLocktime = Buffer.alloc(4)
    prevTxExpanderLocktime.writeUInt32LE(expanderTx0.nLockTime)

    prevAggregationDataPrevH0 = Buffer.from(withdrawalTree.levels[1][0], 'hex')
    prevAggregationDataPrevH1 = Buffer.from(withdrawalTree.levels[1][1], 'hex')
    prevAggregationDataSumAmt = Buffer.alloc(2) // Bigint witnesses need to be minimally encoded! TODO: Do this automatically.
    prevAggregationDataSumAmt.writeInt16LE(Number(expanderAmt))

    currentAggregationDataPrevH0 = Buffer.from(withdrawalTree.levels[0][0], 'hex')
    currentAggregationDataPrevH1 = Buffer.from(withdrawalTree.levels[0][1], 'hex')
    currentAggregationDataSumAmt = Buffer.alloc(2) // Bigint witnesses need to be minimally encoded! TODO: Do this automatically.
    currentAggregationDataSumAmt.writeInt16LE(splitAmt0 + splitAmt1)

    nextAggregationData0PrevH0 = Buffer.from('', 'hex')
    nextAggregationData0PrevH1 = Buffer.from('', 'hex')
    nextAggregationData0SumAmt = Buffer.from('', 'hex')

    nextAggregationData1PrevH0 = Buffer.from('', 'hex')
    nextAggregationData1PrevH1 = Buffer.from('', 'hex')
    nextAggregationData1SumAmt = Buffer.from('', 'hex')

    isExpandingLeaves = Buffer.from('', 'hex')

    withdrawalData0AddressBuff = Buffer.from(withdrawalDataList[0].address, 'hex')
    withdrawalData0AmtBuff = Buffer.alloc(2) // Bigint witnesses need to be minimally encoded! TODO: Do this automatically.
    withdrawalData0AmtBuff.writeInt16LE(Number(withdrawalDataList[0].amount))

    withdrawalData1AddressBuff = Buffer.from(withdrawalDataList[1].address, 'hex')
    withdrawalData1AmtBuff = Buffer.alloc(2) // Bigint witnesses need to be minimally encoded! TODO: Do this automatically.
    withdrawalData1AmtBuff.writeInt16LE(Number(withdrawalDataList[1].amount))

    isLastAggregationLevel = Buffer.from('01', 'hex')

    fundingPrevoutBW = new btc.encoding.BufferWriter()
    fundingPrevoutBW.writeReverse(expanderTx1.inputs[1].prevTxId);
    fundingPrevoutBW.writeInt32LE(expanderTx1.inputs[1].outputIndex);
    fundingPrevout = fundingPrevoutBW.toBuffer()

    witnesses = [
        schnorrTrickData.preimageParts.txVersion,
        schnorrTrickData.preimageParts.nLockTime,
        schnorrTrickData.preimageParts.hashPrevouts,
        schnorrTrickData.preimageParts.hashSpentAmounts,
        schnorrTrickData.preimageParts.hashScripts,
        schnorrTrickData.preimageParts.hashSequences,
        schnorrTrickData.preimageParts.hashOutputs,
        schnorrTrickData.preimageParts.spendType,
        schnorrTrickData.preimageParts.inputNumber,
        schnorrTrickData.preimageParts.tapleafHash,
        schnorrTrickData.preimageParts.keyVersion,
        schnorrTrickData.preimageParts.codeseparatorPosition,
        schnorrTrickData.sighash.hash,
        schnorrTrickData._e,
        Buffer.from([schnorrTrickData.eLastByte]),

        sigOperator,

        isExpandingPrevTxFirstOutput,
        isPrevTxBridge,

        prevTxBridgeVer,
        prevTxBridgeInputs,
        prevTxBridgeContractSPK,
        prevTxBridgeExpanderSPK,
        prevTxBridgeContractAmt,
        prevTxBridgeAccountsRoot,
        prevTxBridgeExpanderRoot,
        prevTxBridgeExpanderAmt,
        prevTxBridgeDepositAggregatorSPK,
        prevTxBridgeWithdrawalAggregatorSPK,
        prevTxBridgeLocktime,

        prevTxExpanderVer,
        prevTxExpanderInputContract,
        prevTxExpanderInputFee,
        prevTxExpanderContractSPK,
        prevTxExpanderOutput0Amt,
        prevTxExpanderOutput1Amt,
        prevTxExpanderHashData,
        prevTxExpanderLocktime,

        prevAggregationDataPrevH0,
        prevAggregationDataPrevH1,
        prevAggregationDataSumAmt,

        currentAggregationDataPrevH0,
        currentAggregationDataPrevH1,
        currentAggregationDataSumAmt,

        nextAggregationData0PrevH0,
        nextAggregationData0PrevH1,
        nextAggregationData0SumAmt,

        nextAggregationData1PrevH0,
        nextAggregationData1PrevH1,
        nextAggregationData1SumAmt,

        isExpandingLeaves,

        withdrawalData0AddressBuff,
        withdrawalData0AmtBuff,

        withdrawalData1AddressBuff,
        withdrawalData1AmtBuff,

        isLastAggregationLevel,

        fundingPrevout,

        scriptExpander.toBuffer(),
        Buffer.from(cblockExpander, 'hex')
    ]

    expanderTx1.inputs[0].witnesses = witnesses


    /////////////////////////////////
    // Expansion of second branch. //
    /////////////////////////////////
    expanderUTXO = {
        txId: expanderTx0.id,
        outputIndex: 1,
        script: scriptExpanderP2TR,
        satoshis: expanderTx0.outputs[1].satoshis
    }
    fundingUTXO = {
        address: operatorAddress.toString(),
        txId: txFunds.id,
        outputIndex: 1,
        script: new btc.Script(operatorAddress),
        satoshis: txFunds.outputs[1].satoshis
    }

    splitAmt0 = Number(withdrawalDataList[2].amount)
    splitAmt1 = Number(withdrawalDataList[3].amount)

    aggregationHash = withdrawalTree.levels[1][1]

    opRetScript = new btc.Script(`6a20${aggregationHash}`)

    const expanderTx2 = new btc.Transaction()
        .from(
            [
                expanderUTXO,
                fundingUTXO
            ]
        )
        .addOutput(new btc.Transaction.Output({
            satoshis: splitAmt0,
            script: scriptExpanderP2TR
        }))
        .addOutput(new btc.Transaction.Output({
            satoshis: splitAmt1,
            script: scriptExpanderP2TR
        }))
        .addOutput(new btc.Transaction.Output({
            satoshis: 0,
            script: opRetScript
        }))
        .sign(operatorPrivateKey)

    schnorrTrickData = await schnorrTrick(expanderTx2, tapleafExpander, 0)
    sigOperator = btc.crypto.Schnorr.sign(operatorPrivateKey, schnorrTrickData.sighash.hash);

    isExpandingPrevTxFirstOutput = Buffer.from('', 'hex')
    isPrevTxBridge = Buffer.from('', 'hex')

    prevTxBridgeVer = Buffer.from('', 'hex')
    prevTxBridgeLocktime = Buffer.from('', 'hex')
    prevTxBridgeInputs = Buffer.from('', 'hex')
    prevTxBridgeContractAmt = Buffer.from('', 'hex')
    prevTxBridgeContractSPK = Buffer.from('', 'hex')
    prevTxBridgeExpanderSPK = Buffer.from('', 'hex')
    prevTxBridgeAccountsRoot = Buffer.from('', 'hex')
    prevTxBridgeExpanderRoot = Buffer.from('', 'hex')
    prevTxBridgeExpanderAmt = Buffer.from('', 'hex')
    prevTxBridgeDepositAggregatorSPK = Buffer.from('', 'hex')
    prevTxBridgeWithdrawalAggregatorSPK = Buffer.from('', 'hex')

    prevTxExpanderVer = Buffer.alloc(4)
    prevTxExpanderVer.writeUInt32LE(expanderTx0.version)
    prevTxExpanderInputContractBW = new btc.encoding.BufferWriter()
    expanderTx0.inputs[0].toBufferWriter(prevTxExpanderInputContractBW);
    prevTxExpanderInputContract = prevTxExpanderInputContractBW.toBuffer()
    prevTxExpanderInputFeeBW = new btc.encoding.BufferWriter()
    expanderTx0.inputs[1].toBufferWriter(prevTxExpanderInputFeeBW);
    prevTxExpanderInputFee = prevTxExpanderInputFeeBW.toBuffer()
    prevTxExpanderContractSPK = Buffer.concat([Buffer.from('22', 'hex'), scriptExpanderP2TR.toBuffer()])
    prevTxExpanderOutput0Amt = Buffer.alloc(2) // Bigint witnesses need to be minimally encoded! TODO: Do this automatically.
    prevTxExpanderOutput0Amt.writeInt16LE(expanderTx0.outputs[0].satoshis)
    prevTxExpanderOutput1Amt = Buffer.alloc(2) // Bigint witnesses need to be minimally encoded! TODO: Do this automatically.
    prevTxExpanderOutput1Amt.writeInt16LE(expanderTx0.outputs[1].satoshis)
    prevTxExpanderHashData = Buffer.from(expanderRoot, 'hex')
    prevTxExpanderLocktime = Buffer.alloc(4)
    prevTxExpanderLocktime.writeUInt32LE(expanderTx0.nLockTime)

    prevAggregationDataPrevH0 = Buffer.from(withdrawalTree.levels[1][0], 'hex')
    prevAggregationDataPrevH1 = Buffer.from(withdrawalTree.levels[1][1], 'hex')
    prevAggregationDataSumAmt = Buffer.alloc(2) // Bigint witnesses need to be minimally encoded! TODO: Do this automatically.
    prevAggregationDataSumAmt.writeInt16LE(Number(expanderAmt))

    currentAggregationDataPrevH0 = Buffer.from(withdrawalTree.levels[0][2], 'hex')
    currentAggregationDataPrevH1 = Buffer.from(withdrawalTree.levels[0][3], 'hex')
    currentAggregationDataSumAmt = Buffer.alloc(2) // Bigint witnesses need to be minimally encoded! TODO: Do this automatically.
    currentAggregationDataSumAmt.writeInt16LE(splitAmt0 + splitAmt1)

    nextAggregationData0PrevH0 = Buffer.from('', 'hex')
    nextAggregationData0PrevH1 = Buffer.from('', 'hex')
    nextAggregationData0SumAmt = Buffer.from('', 'hex')

    nextAggregationData1PrevH0 = Buffer.from('', 'hex')
    nextAggregationData1PrevH1 = Buffer.from('', 'hex')
    nextAggregationData1SumAmt = Buffer.from('', 'hex')

    isExpandingLeaves = Buffer.from('', 'hex')

    withdrawalData0AddressBuff = Buffer.from(withdrawalDataList[2].address, 'hex')
    withdrawalData0AmtBuff = Buffer.alloc(2) // Bigint witnesses need to be minimally encoded! TODO: Do this automatically.
    withdrawalData0AmtBuff.writeInt16LE(Number(withdrawalDataList[2].amount))

    withdrawalData1AddressBuff = Buffer.from(withdrawalDataList[3].address, 'hex')
    withdrawalData1AmtBuff = Buffer.alloc(2) // Bigint witnesses need to be minimally encoded! TODO: Do this automatically.
    withdrawalData1AmtBuff.writeInt16LE(Number(withdrawalDataList[3].amount))

    isLastAggregationLevel = Buffer.from('01', 'hex')

    fundingPrevoutBW = new btc.encoding.BufferWriter()
    fundingPrevoutBW.writeReverse(expanderTx2.inputs[1].prevTxId);
    fundingPrevoutBW.writeInt32LE(expanderTx2.inputs[1].outputIndex);
    fundingPrevout = fundingPrevoutBW.toBuffer()

    witnesses = [
        schnorrTrickData.preimageParts.txVersion,
        schnorrTrickData.preimageParts.nLockTime,
        schnorrTrickData.preimageParts.hashPrevouts,
        schnorrTrickData.preimageParts.hashSpentAmounts,
        schnorrTrickData.preimageParts.hashScripts,
        schnorrTrickData.preimageParts.hashSequences,
        schnorrTrickData.preimageParts.hashOutputs,
        schnorrTrickData.preimageParts.spendType,
        schnorrTrickData.preimageParts.inputNumber,
        schnorrTrickData.preimageParts.tapleafHash,
        schnorrTrickData.preimageParts.keyVersion,
        schnorrTrickData.preimageParts.codeseparatorPosition,
        schnorrTrickData.sighash.hash,
        schnorrTrickData._e,
        Buffer.from([schnorrTrickData.eLastByte]),

        sigOperator,

        isExpandingPrevTxFirstOutput,
        isPrevTxBridge,

        prevTxBridgeVer,
        prevTxBridgeInputs,
        prevTxBridgeContractSPK,
        prevTxBridgeExpanderSPK,
        prevTxBridgeContractAmt,
        prevTxBridgeAccountsRoot,
        prevTxBridgeExpanderRoot,
        prevTxBridgeExpanderAmt,
        prevTxBridgeDepositAggregatorSPK,
        prevTxBridgeWithdrawalAggregatorSPK,
        prevTxBridgeLocktime,

        prevTxExpanderVer,
        prevTxExpanderInputContract,
        prevTxExpanderInputFee,
        prevTxExpanderContractSPK,
        prevTxExpanderOutput0Amt,
        prevTxExpanderOutput1Amt,
        prevTxExpanderHashData,
        prevTxExpanderLocktime,

        prevAggregationDataPrevH0,
        prevAggregationDataPrevH1,
        prevAggregationDataSumAmt,

        currentAggregationDataPrevH0,
        currentAggregationDataPrevH1,
        currentAggregationDataSumAmt,

        nextAggregationData0PrevH0,
        nextAggregationData0PrevH1,
        nextAggregationData0SumAmt,

        nextAggregationData1PrevH0,
        nextAggregationData1PrevH1,
        nextAggregationData1SumAmt,

        isExpandingLeaves,

        withdrawalData0AddressBuff,
        withdrawalData0AmtBuff,

        withdrawalData1AddressBuff,
        withdrawalData1AmtBuff,

        isLastAggregationLevel,

        fundingPrevout,

        scriptExpander.toBuffer(),
        Buffer.from(cblockExpander, 'hex')
    ]

    expanderTx2.inputs[0].witnesses = witnesses

    ///////////////////////
    // Expansion leaf 0. //
    ///////////////////////
    expanderUTXO = {
        txId: expanderTx1.id,
        outputIndex: 0,
        script: scriptExpanderP2TR,
        satoshis: expanderTx1.outputs[0].satoshis
    }
    fundingUTXO = {
        address: operatorAddress.toString(),
        txId: txFunds.id,
        outputIndex: 2,
        script: new btc.Script(operatorAddress),
        satoshis: txFunds.outputs[2].satoshis
    }

    splitAmt0 = Number(withdrawalDataList[0].amount)
    splitAmt1 = Number(withdrawalDataList[1].amount)

    const expanderTx3 = new btc.Transaction()
        .from(
            [
                expanderUTXO,
                fundingUTXO
            ]
        )
        .addOutput(new btc.Transaction.Output({
            satoshis: splitAmt0,
            script: new btc.Script(operatorAddress)
        }))
        .sign(operatorPrivateKey)

    schnorrTrickData = await schnorrTrick(expanderTx3, tapleafExpander, 0)
    sigOperator = btc.crypto.Schnorr.sign(operatorPrivateKey, schnorrTrickData.sighash.hash);

    isExpandingPrevTxFirstOutput = Buffer.from('01', 'hex')
    isPrevTxBridge = Buffer.from('', 'hex')

    prevTxBridgeVer = Buffer.from('', 'hex')
    prevTxBridgeLocktime = Buffer.from('', 'hex')
    prevTxBridgeInputs = Buffer.from('', 'hex')
    prevTxBridgeContractAmt = Buffer.from('', 'hex')
    prevTxBridgeContractSPK = Buffer.from('', 'hex')
    prevTxBridgeExpanderSPK = Buffer.from('', 'hex')
    prevTxBridgeAccountsRoot = Buffer.from('', 'hex')
    prevTxBridgeExpanderRoot = Buffer.from('', 'hex')
    prevTxBridgeExpanderAmt = Buffer.from('', 'hex')
    prevTxBridgeDepositAggregatorSPK = Buffer.from('', 'hex')
    prevTxBridgeWithdrawalAggregatorSPK = Buffer.from('', 'hex')

    prevTxExpanderVer = Buffer.alloc(4)
    prevTxExpanderVer.writeUInt32LE(expanderTx1.version)
    prevTxExpanderInputContractBW = new btc.encoding.BufferWriter()
    expanderTx1.inputs[0].toBufferWriter(prevTxExpanderInputContractBW);
    prevTxExpanderInputContract = prevTxExpanderInputContractBW.toBuffer()
    prevTxExpanderInputFeeBW = new btc.encoding.BufferWriter()
    expanderTx1.inputs[1].toBufferWriter(prevTxExpanderInputFeeBW);
    prevTxExpanderInputFee = prevTxExpanderInputFeeBW.toBuffer()
    prevTxExpanderContractSPK = Buffer.concat([Buffer.from('22', 'hex'), scriptExpanderP2TR.toBuffer()])
    prevTxExpanderOutput0Amt = Buffer.alloc(2) // Bigint witnesses need to be minimally encoded! TODO: Do this automatically.
    prevTxExpanderOutput0Amt.writeInt16LE(expanderTx1.outputs[0].satoshis)
    prevTxExpanderOutput1Amt = Buffer.alloc(2) // Bigint witnesses need to be minimally encoded! TODO: Do this automatically.
    prevTxExpanderOutput1Amt.writeInt16LE(expanderTx1.outputs[1].satoshis)
    prevTxExpanderHashData = Buffer.from(withdrawalTree.levels[1][0], 'hex')
    prevTxExpanderLocktime = Buffer.alloc(4)
    prevTxExpanderLocktime.writeUInt32LE(expanderTx1.nLockTime)

    prevAggregationDataPrevH0 = Buffer.from(withdrawalTree.levels[0][0], 'hex')
    prevAggregationDataPrevH1 = Buffer.from(withdrawalTree.levels[0][1], 'hex')
    prevAggregationDataSumAmt = Buffer.alloc(2) // Bigint witnesses need to be minimally encoded! TODO: Do this automatically.
    prevAggregationDataSumAmt.writeInt16LE(splitAmt0 + splitAmt1)

    currentAggregationDataPrevH0 = Buffer.from('', 'hex')
    currentAggregationDataPrevH1 = Buffer.from('', 'hex')
    currentAggregationDataSumAmt = Buffer.from('', 'hex')

    nextAggregationData0PrevH0 = Buffer.from('', 'hex')
    nextAggregationData0PrevH1 = Buffer.from('', 'hex')
    nextAggregationData0SumAmt = Buffer.from('', 'hex')

    nextAggregationData1PrevH0 = Buffer.from('', 'hex')
    nextAggregationData1PrevH1 = Buffer.from('', 'hex')
    nextAggregationData1SumAmt = Buffer.from('', 'hex')

    isExpandingLeaves = Buffer.from('01', 'hex')

    withdrawalData0AddressBuff = Buffer.from(withdrawalDataList[0].address, 'hex')
    withdrawalData0AmtBuff = Buffer.alloc(2) // Bigint witnesses need to be minimally encoded! TODO: Do this automatically.
    withdrawalData0AmtBuff.writeInt16LE(Number(withdrawalDataList[0].amount))

    withdrawalData1AddressBuff = Buffer.from(withdrawalDataList[1].address, 'hex')
    withdrawalData1AmtBuff = Buffer.alloc(2) // Bigint witnesses need to be minimally encoded! TODO: Do this automatically.
    withdrawalData1AmtBuff.writeInt16LE(Number(withdrawalDataList[1].amount))

    isLastAggregationLevel = Buffer.from('', 'hex')

    fundingPrevoutBW = new btc.encoding.BufferWriter()
    fundingPrevoutBW.writeReverse(expanderTx3.inputs[1].prevTxId);
    fundingPrevoutBW.writeInt32LE(expanderTx3.inputs[1].outputIndex);
    fundingPrevout = fundingPrevoutBW.toBuffer()

    witnesses = [
        schnorrTrickData.preimageParts.txVersion,
        schnorrTrickData.preimageParts.nLockTime,
        schnorrTrickData.preimageParts.hashPrevouts,
        schnorrTrickData.preimageParts.hashSpentAmounts,
        schnorrTrickData.preimageParts.hashScripts,
        schnorrTrickData.preimageParts.hashSequences,
        schnorrTrickData.preimageParts.hashOutputs,
        schnorrTrickData.preimageParts.spendType,
        schnorrTrickData.preimageParts.inputNumber,
        schnorrTrickData.preimageParts.tapleafHash,
        schnorrTrickData.preimageParts.keyVersion,
        schnorrTrickData.preimageParts.codeseparatorPosition,
        schnorrTrickData.sighash.hash,
        schnorrTrickData._e,
        Buffer.from([schnorrTrickData.eLastByte]),

        sigOperator,

        isExpandingPrevTxFirstOutput,
        isPrevTxBridge,

        prevTxBridgeVer,
        prevTxBridgeInputs,
        prevTxBridgeContractSPK,
        prevTxBridgeExpanderSPK,
        prevTxBridgeContractAmt,
        prevTxBridgeAccountsRoot,
        prevTxBridgeExpanderRoot,
        prevTxBridgeExpanderAmt,
        prevTxBridgeDepositAggregatorSPK,
        prevTxBridgeWithdrawalAggregatorSPK,
        prevTxBridgeLocktime,

        prevTxExpanderVer,
        prevTxExpanderInputContract,
        prevTxExpanderInputFee,
        prevTxExpanderContractSPK,
        prevTxExpanderOutput0Amt,
        prevTxExpanderOutput1Amt,
        prevTxExpanderHashData,
        prevTxExpanderLocktime,

        prevAggregationDataPrevH0,
        prevAggregationDataPrevH1,
        prevAggregationDataSumAmt,

        currentAggregationDataPrevH0,
        currentAggregationDataPrevH1,
        currentAggregationDataSumAmt,

        nextAggregationData0PrevH0,
        nextAggregationData0PrevH1,
        nextAggregationData0SumAmt,

        nextAggregationData1PrevH0,
        nextAggregationData1PrevH1,
        nextAggregationData1SumAmt,

        isExpandingLeaves,

        withdrawalData0AddressBuff,
        withdrawalData0AmtBuff,

        withdrawalData1AddressBuff,
        withdrawalData1AmtBuff,

        isLastAggregationLevel,

        fundingPrevout,

        scriptExpander.toBuffer(),
        Buffer.from(cblockExpander, 'hex')
    ]

    expanderTx3.inputs[0].witnesses = witnesses


    ///////////////////////
    // Expansion leaf 1. //
    ///////////////////////
    expanderUTXO = {
        txId: expanderTx1.id,
        outputIndex: 1,
        script: scriptExpanderP2TR,
        satoshis: expanderTx1.outputs[1].satoshis
    }
    fundingUTXO = {
        address: operatorAddress.toString(),
        txId: txFunds.id,
        outputIndex: 3,
        script: new btc.Script(operatorAddress),
        satoshis: txFunds.outputs[3].satoshis
    }

    splitAmt0 = Number(withdrawalDataList[0].amount)
    splitAmt1 = Number(withdrawalDataList[1].amount)

    const expanderTx4 = new btc.Transaction()
        .from(
            [
                expanderUTXO,
                fundingUTXO
            ]
        )
        .addOutput(new btc.Transaction.Output({
            satoshis: splitAmt1,
            script: new btc.Script(operatorAddress)
        }))
        .sign(operatorPrivateKey)

    schnorrTrickData = await schnorrTrick(expanderTx4, tapleafExpander, 0)
    sigOperator = btc.crypto.Schnorr.sign(operatorPrivateKey, schnorrTrickData.sighash.hash);

    isExpandingPrevTxFirstOutput = Buffer.from('', 'hex')
    isPrevTxBridge = Buffer.from('', 'hex')

    prevTxBridgeVer = Buffer.from('', 'hex')
    prevTxBridgeLocktime = Buffer.from('', 'hex')
    prevTxBridgeInputs = Buffer.from('', 'hex')
    prevTxBridgeContractAmt = Buffer.from('', 'hex')
    prevTxBridgeContractSPK = Buffer.from('', 'hex')
    prevTxBridgeExpanderSPK = Buffer.from('', 'hex')
    prevTxBridgeAccountsRoot = Buffer.from('', 'hex')
    prevTxBridgeExpanderRoot = Buffer.from('', 'hex')
    prevTxBridgeExpanderAmt = Buffer.from('', 'hex')
    prevTxBridgeDepositAggregatorSPK = Buffer.from('', 'hex')
    prevTxBridgeWithdrawalAggregatorSPK = Buffer.from('', 'hex')

    prevTxExpanderVer = Buffer.alloc(4)
    prevTxExpanderVer.writeUInt32LE(expanderTx1.version)
    prevTxExpanderInputContractBW = new btc.encoding.BufferWriter()
    expanderTx1.inputs[0].toBufferWriter(prevTxExpanderInputContractBW);
    prevTxExpanderInputContract = prevTxExpanderInputContractBW.toBuffer()
    prevTxExpanderInputFeeBW = new btc.encoding.BufferWriter()
    expanderTx1.inputs[1].toBufferWriter(prevTxExpanderInputFeeBW);
    prevTxExpanderInputFee = prevTxExpanderInputFeeBW.toBuffer()
    prevTxExpanderContractSPK = Buffer.concat([Buffer.from('22', 'hex'), scriptExpanderP2TR.toBuffer()])
    prevTxExpanderOutput0Amt = Buffer.alloc(2) // Bigint witnesses need to be minimally encoded! TODO: Do this automatically.
    prevTxExpanderOutput0Amt.writeInt16LE(expanderTx1.outputs[0].satoshis)
    prevTxExpanderOutput1Amt = Buffer.alloc(2) // Bigint witnesses need to be minimally encoded! TODO: Do this automatically.
    prevTxExpanderOutput1Amt.writeInt16LE(expanderTx1.outputs[1].satoshis)
    prevTxExpanderHashData = Buffer.from(withdrawalTree.levels[1][0], 'hex')
    prevTxExpanderLocktime = Buffer.alloc(4)
    prevTxExpanderLocktime.writeUInt32LE(expanderTx1.nLockTime)

    prevAggregationDataPrevH0 = Buffer.from(withdrawalTree.levels[0][0], 'hex')
    prevAggregationDataPrevH1 = Buffer.from(withdrawalTree.levels[0][1], 'hex')
    prevAggregationDataSumAmt = Buffer.alloc(2) // Bigint witnesses need to be minimally encoded! TODO: Do this automatically.
    prevAggregationDataSumAmt.writeInt16LE(splitAmt0 + splitAmt1)

    currentAggregationDataPrevH0 = Buffer.from('', 'hex')
    currentAggregationDataPrevH1 = Buffer.from('', 'hex')
    currentAggregationDataSumAmt = Buffer.from('', 'hex')

    nextAggregationData0PrevH0 = Buffer.from('', 'hex')
    nextAggregationData0PrevH1 = Buffer.from('', 'hex')
    nextAggregationData0SumAmt = Buffer.from('', 'hex')

    nextAggregationData1PrevH0 = Buffer.from('', 'hex')
    nextAggregationData1PrevH1 = Buffer.from('', 'hex')
    nextAggregationData1SumAmt = Buffer.from('', 'hex')

    isExpandingLeaves = Buffer.from('01', 'hex')

    withdrawalData0AddressBuff = Buffer.from(withdrawalDataList[0].address, 'hex')
    withdrawalData0AmtBuff = Buffer.alloc(2) // Bigint witnesses need to be minimally encoded! TODO: Do this automatically.
    withdrawalData0AmtBuff.writeInt16LE(Number(withdrawalDataList[0].amount))

    withdrawalData1AddressBuff = Buffer.from(withdrawalDataList[1].address, 'hex')
    withdrawalData1AmtBuff = Buffer.alloc(2) // Bigint witnesses need to be minimally encoded! TODO: Do this automatically.
    withdrawalData1AmtBuff.writeInt16LE(Number(withdrawalDataList[1].amount))

    isLastAggregationLevel = Buffer.from('', 'hex')

    fundingPrevoutBW = new btc.encoding.BufferWriter()
    fundingPrevoutBW.writeReverse(expanderTx4.inputs[1].prevTxId);
    fundingPrevoutBW.writeInt32LE(expanderTx4.inputs[1].outputIndex);
    fundingPrevout = fundingPrevoutBW.toBuffer()

    witnesses = [
        schnorrTrickData.preimageParts.txVersion,
        schnorrTrickData.preimageParts.nLockTime,
        schnorrTrickData.preimageParts.hashPrevouts,
        schnorrTrickData.preimageParts.hashSpentAmounts,
        schnorrTrickData.preimageParts.hashScripts,
        schnorrTrickData.preimageParts.hashSequences,
        schnorrTrickData.preimageParts.hashOutputs,
        schnorrTrickData.preimageParts.spendType,
        schnorrTrickData.preimageParts.inputNumber,
        schnorrTrickData.preimageParts.tapleafHash,
        schnorrTrickData.preimageParts.keyVersion,
        schnorrTrickData.preimageParts.codeseparatorPosition,
        schnorrTrickData.sighash.hash,
        schnorrTrickData._e,
        Buffer.from([schnorrTrickData.eLastByte]),

        sigOperator,

        isExpandingPrevTxFirstOutput,
        isPrevTxBridge,

        prevTxBridgeVer,
        prevTxBridgeInputs,
        prevTxBridgeContractSPK,
        prevTxBridgeExpanderSPK,
        prevTxBridgeContractAmt,
        prevTxBridgeAccountsRoot,
        prevTxBridgeExpanderRoot,
        prevTxBridgeExpanderAmt,
        prevTxBridgeDepositAggregatorSPK,
        prevTxBridgeWithdrawalAggregatorSPK,
        prevTxBridgeLocktime,

        prevTxExpanderVer,
        prevTxExpanderInputContract,
        prevTxExpanderInputFee,
        prevTxExpanderContractSPK,
        prevTxExpanderOutput0Amt,
        prevTxExpanderOutput1Amt,
        prevTxExpanderHashData,
        prevTxExpanderLocktime,

        prevAggregationDataPrevH0,
        prevAggregationDataPrevH1,
        prevAggregationDataSumAmt,

        currentAggregationDataPrevH0,
        currentAggregationDataPrevH1,
        currentAggregationDataSumAmt,

        nextAggregationData0PrevH0,
        nextAggregationData0PrevH1,
        nextAggregationData0SumAmt,

        nextAggregationData1PrevH0,
        nextAggregationData1PrevH1,
        nextAggregationData1SumAmt,

        isExpandingLeaves,

        withdrawalData0AddressBuff,
        withdrawalData0AmtBuff,

        withdrawalData1AddressBuff,
        withdrawalData1AmtBuff,

        isLastAggregationLevel,

        fundingPrevout,

        scriptExpander.toBuffer(),
        Buffer.from(cblockExpander, 'hex')
    ]

    expanderTx4.inputs[0].witnesses = witnesses

    ///////////////////////
    // Expansion leaf 2. //
    ///////////////////////
    expanderUTXO = {
        txId: expanderTx2.id,
        outputIndex: 0,
        script: scriptExpanderP2TR,
        satoshis: expanderTx2.outputs[0].satoshis
    }
    fundingUTXO = {
        address: operatorAddress.toString(),
        txId: txFunds.id,
        outputIndex: 4,
        script: new btc.Script(operatorAddress),
        satoshis: txFunds.outputs[4].satoshis
    }

    splitAmt0 = Number(withdrawalDataList[2].amount)
    splitAmt1 = Number(withdrawalDataList[3].amount)

    const expanderTx5 = new btc.Transaction()
        .from(
            [
                expanderUTXO,
                fundingUTXO
            ]
        )
        .addOutput(new btc.Transaction.Output({
            satoshis: splitAmt0,
            script: new btc.Script(operatorAddress)
        }))
        .sign(operatorPrivateKey)

    schnorrTrickData = await schnorrTrick(expanderTx5, tapleafExpander, 0)
    sigOperator = btc.crypto.Schnorr.sign(operatorPrivateKey, schnorrTrickData.sighash.hash);

    isExpandingPrevTxFirstOutput = Buffer.from('01', 'hex')
    isPrevTxBridge = Buffer.from('', 'hex')

    prevTxBridgeVer = Buffer.from('', 'hex')
    prevTxBridgeLocktime = Buffer.from('', 'hex')
    prevTxBridgeInputs = Buffer.from('', 'hex')
    prevTxBridgeContractAmt = Buffer.from('', 'hex')
    prevTxBridgeContractSPK = Buffer.from('', 'hex')
    prevTxBridgeExpanderSPK = Buffer.from('', 'hex')
    prevTxBridgeAccountsRoot = Buffer.from('', 'hex')
    prevTxBridgeExpanderRoot = Buffer.from('', 'hex')
    prevTxBridgeExpanderAmt = Buffer.from('', 'hex')
    prevTxBridgeDepositAggregatorSPK = Buffer.from('', 'hex')
    prevTxBridgeWithdrawalAggregatorSPK = Buffer.from('', 'hex')

    prevTxExpanderVer = Buffer.alloc(4)
    prevTxExpanderVer.writeUInt32LE(expanderTx2.version)
    prevTxExpanderInputContractBW = new btc.encoding.BufferWriter()
    expanderTx2.inputs[0].toBufferWriter(prevTxExpanderInputContractBW);
    prevTxExpanderInputContract = prevTxExpanderInputContractBW.toBuffer()
    prevTxExpanderInputFeeBW = new btc.encoding.BufferWriter()
    expanderTx2.inputs[1].toBufferWriter(prevTxExpanderInputFeeBW);
    prevTxExpanderInputFee = prevTxExpanderInputFeeBW.toBuffer()
    prevTxExpanderContractSPK = Buffer.concat([Buffer.from('22', 'hex'), scriptExpanderP2TR.toBuffer()])
    prevTxExpanderOutput0Amt = Buffer.alloc(2) // Bigint witnesses need to be minimally encoded! TODO: Do this automatically.
    prevTxExpanderOutput0Amt.writeInt16LE(expanderTx2.outputs[0].satoshis)
    prevTxExpanderOutput1Amt = Buffer.alloc(2) // Bigint witnesses need to be minimally encoded! TODO: Do this automatically.
    prevTxExpanderOutput1Amt.writeInt16LE(expanderTx2.outputs[1].satoshis)
    prevTxExpanderHashData = Buffer.from(withdrawalTree.levels[1][1], 'hex')
    prevTxExpanderLocktime = Buffer.alloc(4)
    prevTxExpanderLocktime.writeUInt32LE(expanderTx2.nLockTime)

    prevAggregationDataPrevH0 = Buffer.from(withdrawalTree.levels[0][2], 'hex')
    prevAggregationDataPrevH1 = Buffer.from(withdrawalTree.levels[0][3], 'hex')
    prevAggregationDataSumAmt = Buffer.alloc(2) // Bigint witnesses need to be minimally encoded! TODO: Do this automatically.
    prevAggregationDataSumAmt.writeInt16LE(splitAmt0 + splitAmt1)

    currentAggregationDataPrevH0 = Buffer.from('', 'hex')
    currentAggregationDataPrevH1 = Buffer.from('', 'hex')
    currentAggregationDataSumAmt = Buffer.from('', 'hex')

    nextAggregationData0PrevH0 = Buffer.from('', 'hex')
    nextAggregationData0PrevH1 = Buffer.from('', 'hex')
    nextAggregationData0SumAmt = Buffer.from('', 'hex')

    nextAggregationData1PrevH0 = Buffer.from('', 'hex')
    nextAggregationData1PrevH1 = Buffer.from('', 'hex')
    nextAggregationData1SumAmt = Buffer.from('', 'hex')

    isExpandingLeaves = Buffer.from('01', 'hex')

    withdrawalData0AddressBuff = Buffer.from(withdrawalDataList[2].address, 'hex')
    withdrawalData0AmtBuff = Buffer.alloc(2) // Bigint witnesses need to be minimally encoded! TODO: Do this automatically.
    withdrawalData0AmtBuff.writeInt16LE(Number(withdrawalDataList[2].amount))

    withdrawalData1AddressBuff = Buffer.from(withdrawalDataList[3].address, 'hex')
    withdrawalData1AmtBuff = Buffer.alloc(2) // Bigint witnesses need to be minimally encoded! TODO: Do this automatically.
    withdrawalData1AmtBuff.writeInt16LE(Number(withdrawalDataList[3].amount))

    isLastAggregationLevel = Buffer.from('', 'hex')

    fundingPrevoutBW = new btc.encoding.BufferWriter()
    fundingPrevoutBW.writeReverse(expanderTx5.inputs[1].prevTxId);
    fundingPrevoutBW.writeInt32LE(expanderTx5.inputs[1].outputIndex);
    fundingPrevout = fundingPrevoutBW.toBuffer()

    witnesses = [
        schnorrTrickData.preimageParts.txVersion,
        schnorrTrickData.preimageParts.nLockTime,
        schnorrTrickData.preimageParts.hashPrevouts,
        schnorrTrickData.preimageParts.hashSpentAmounts,
        schnorrTrickData.preimageParts.hashScripts,
        schnorrTrickData.preimageParts.hashSequences,
        schnorrTrickData.preimageParts.hashOutputs,
        schnorrTrickData.preimageParts.spendType,
        schnorrTrickData.preimageParts.inputNumber,
        schnorrTrickData.preimageParts.tapleafHash,
        schnorrTrickData.preimageParts.keyVersion,
        schnorrTrickData.preimageParts.codeseparatorPosition,
        schnorrTrickData.sighash.hash,
        schnorrTrickData._e,
        Buffer.from([schnorrTrickData.eLastByte]),

        sigOperator,

        isExpandingPrevTxFirstOutput,
        isPrevTxBridge,

        prevTxBridgeVer,
        prevTxBridgeInputs,
        prevTxBridgeContractSPK,
        prevTxBridgeExpanderSPK,
        prevTxBridgeContractAmt,
        prevTxBridgeAccountsRoot,
        prevTxBridgeExpanderRoot,
        prevTxBridgeExpanderAmt,
        prevTxBridgeDepositAggregatorSPK,
        prevTxBridgeWithdrawalAggregatorSPK,
        prevTxBridgeLocktime,

        prevTxExpanderVer,
        prevTxExpanderInputContract,
        prevTxExpanderInputFee,
        prevTxExpanderContractSPK,
        prevTxExpanderOutput0Amt,
        prevTxExpanderOutput1Amt,
        prevTxExpanderHashData,
        prevTxExpanderLocktime,

        prevAggregationDataPrevH0,
        prevAggregationDataPrevH1,
        prevAggregationDataSumAmt,

        currentAggregationDataPrevH0,
        currentAggregationDataPrevH1,
        currentAggregationDataSumAmt,

        nextAggregationData0PrevH0,
        nextAggregationData0PrevH1,
        nextAggregationData0SumAmt,

        nextAggregationData1PrevH0,
        nextAggregationData1PrevH1,
        nextAggregationData1SumAmt,

        isExpandingLeaves,

        withdrawalData0AddressBuff,
        withdrawalData0AmtBuff,

        withdrawalData1AddressBuff,
        withdrawalData1AmtBuff,

        isLastAggregationLevel,

        fundingPrevout,

        scriptExpander.toBuffer(),
        Buffer.from(cblockExpander, 'hex')
    ]

    expanderTx5.inputs[0].witnesses = witnesses


    ///////////////////////
    // Expansion leaf 3. //
    ///////////////////////
    expanderUTXO = {
        txId: expanderTx2.id,
        outputIndex: 1,
        script: scriptExpanderP2TR,
        satoshis: expanderTx2.outputs[1].satoshis
    }
    fundingUTXO = {
        address: operatorAddress.toString(),
        txId: txFunds.id,
        outputIndex: 5,
        script: new btc.Script(operatorAddress),
        satoshis: txFunds.outputs[5].satoshis
    }

    splitAmt0 = Number(withdrawalDataList[2].amount)
    splitAmt1 = Number(withdrawalDataList[3].amount)

    const expanderTx6 = new btc.Transaction()
        .from(
            [
                expanderUTXO,
                fundingUTXO
            ]
        )
        .addOutput(new btc.Transaction.Output({
            satoshis: splitAmt1,
            script: new btc.Script(operatorAddress)
        }))
        .sign(operatorPrivateKey)

    schnorrTrickData = await schnorrTrick(expanderTx6, tapleafExpander, 0)
    sigOperator = btc.crypto.Schnorr.sign(operatorPrivateKey, schnorrTrickData.sighash.hash);

    isExpandingPrevTxFirstOutput = Buffer.from('', 'hex')
    isPrevTxBridge = Buffer.from('', 'hex')

    prevTxBridgeVer = Buffer.from('', 'hex')
    prevTxBridgeLocktime = Buffer.from('', 'hex')
    prevTxBridgeInputs = Buffer.from('', 'hex')
    prevTxBridgeContractAmt = Buffer.from('', 'hex')
    prevTxBridgeContractSPK = Buffer.from('', 'hex')
    prevTxBridgeExpanderSPK = Buffer.from('', 'hex')
    prevTxBridgeAccountsRoot = Buffer.from('', 'hex')
    prevTxBridgeExpanderRoot = Buffer.from('', 'hex')
    prevTxBridgeExpanderAmt = Buffer.from('', 'hex')
    prevTxBridgeDepositAggregatorSPK = Buffer.from('', 'hex')
    prevTxBridgeWithdrawalAggregatorSPK = Buffer.from('', 'hex')

    prevTxExpanderVer = Buffer.alloc(4)
    prevTxExpanderVer.writeUInt32LE(expanderTx2.version)
    prevTxExpanderInputContractBW = new btc.encoding.BufferWriter()
    expanderTx2.inputs[0].toBufferWriter(prevTxExpanderInputContractBW);
    prevTxExpanderInputContract = prevTxExpanderInputContractBW.toBuffer()
    prevTxExpanderInputFeeBW = new btc.encoding.BufferWriter()
    expanderTx2.inputs[1].toBufferWriter(prevTxExpanderInputFeeBW);
    prevTxExpanderInputFee = prevTxExpanderInputFeeBW.toBuffer()
    prevTxExpanderContractSPK = Buffer.concat([Buffer.from('22', 'hex'), scriptExpanderP2TR.toBuffer()])
    prevTxExpanderOutput0Amt = Buffer.alloc(2) // Bigint witnesses need to be minimally encoded! TODO: Do this automatically.
    prevTxExpanderOutput0Amt.writeInt16LE(expanderTx2.outputs[0].satoshis)
    prevTxExpanderOutput1Amt = Buffer.alloc(2) // Bigint witnesses need to be minimally encoded! TODO: Do this automatically.
    prevTxExpanderOutput1Amt.writeInt16LE(expanderTx2.outputs[1].satoshis)
    prevTxExpanderHashData = Buffer.from(withdrawalTree.levels[1][1], 'hex')
    prevTxExpanderLocktime = Buffer.alloc(4)
    prevTxExpanderLocktime.writeUInt32LE(expanderTx2.nLockTime)

    prevAggregationDataPrevH0 = Buffer.from(withdrawalTree.levels[0][2], 'hex')
    prevAggregationDataPrevH1 = Buffer.from(withdrawalTree.levels[0][3], 'hex')
    prevAggregationDataSumAmt = Buffer.alloc(2) // Bigint witnesses need to be minimally encoded! TODO: Do this automatically.
    prevAggregationDataSumAmt.writeInt16LE(splitAmt0 + splitAmt1)

    currentAggregationDataPrevH0 = Buffer.from('', 'hex')
    currentAggregationDataPrevH1 = Buffer.from('', 'hex')
    currentAggregationDataSumAmt = Buffer.from('', 'hex')

    nextAggregationData0PrevH0 = Buffer.from('', 'hex')
    nextAggregationData0PrevH1 = Buffer.from('', 'hex')
    nextAggregationData0SumAmt = Buffer.from('', 'hex')

    nextAggregationData1PrevH0 = Buffer.from('', 'hex')
    nextAggregationData1PrevH1 = Buffer.from('', 'hex')
    nextAggregationData1SumAmt = Buffer.from('', 'hex')

    isExpandingLeaves = Buffer.from('01', 'hex')

    withdrawalData0AddressBuff = Buffer.from(withdrawalDataList[2].address, 'hex')
    withdrawalData0AmtBuff = Buffer.alloc(2) // Bigint witnesses need to be minimally encoded! TODO: Do this automatically.
    withdrawalData0AmtBuff.writeInt16LE(Number(withdrawalDataList[2].amount))

    withdrawalData1AddressBuff = Buffer.from(withdrawalDataList[3].address, 'hex')
    withdrawalData1AmtBuff = Buffer.alloc(2) // Bigint witnesses need to be minimally encoded! TODO: Do this automatically.
    withdrawalData1AmtBuff.writeInt16LE(Number(withdrawalDataList[3].amount))

    isLastAggregationLevel = Buffer.from('', 'hex')

    fundingPrevoutBW = new btc.encoding.BufferWriter()
    fundingPrevoutBW.writeReverse(expanderTx6.inputs[1].prevTxId);
    fundingPrevoutBW.writeInt32LE(expanderTx6.inputs[1].outputIndex);
    fundingPrevout = fundingPrevoutBW.toBuffer()

    witnesses = [
        schnorrTrickData.preimageParts.txVersion,
        schnorrTrickData.preimageParts.nLockTime,
        schnorrTrickData.preimageParts.hashPrevouts,
        schnorrTrickData.preimageParts.hashSpentAmounts,
        schnorrTrickData.preimageParts.hashScripts,
        schnorrTrickData.preimageParts.hashSequences,
        schnorrTrickData.preimageParts.hashOutputs,
        schnorrTrickData.preimageParts.spendType,
        schnorrTrickData.preimageParts.inputNumber,
        schnorrTrickData.preimageParts.tapleafHash,
        schnorrTrickData.preimageParts.keyVersion,
        schnorrTrickData.preimageParts.codeseparatorPosition,
        schnorrTrickData.sighash.hash,
        schnorrTrickData._e,
        Buffer.from([schnorrTrickData.eLastByte]),

        sigOperator,

        isExpandingPrevTxFirstOutput,
        isPrevTxBridge,

        prevTxBridgeVer,
        prevTxBridgeInputs,
        prevTxBridgeContractSPK,
        prevTxBridgeExpanderSPK,
        prevTxBridgeContractAmt,
        prevTxBridgeAccountsRoot,
        prevTxBridgeExpanderRoot,
        prevTxBridgeExpanderAmt,
        prevTxBridgeDepositAggregatorSPK,
        prevTxBridgeWithdrawalAggregatorSPK,
        prevTxBridgeLocktime,

        prevTxExpanderVer,
        prevTxExpanderInputContract,
        prevTxExpanderInputFee,
        prevTxExpanderContractSPK,
        prevTxExpanderOutput0Amt,
        prevTxExpanderOutput1Amt,
        prevTxExpanderHashData,
        prevTxExpanderLocktime,

        prevAggregationDataPrevH0,
        prevAggregationDataPrevH1,
        prevAggregationDataSumAmt,

        currentAggregationDataPrevH0,
        currentAggregationDataPrevH1,
        currentAggregationDataSumAmt,

        nextAggregationData0PrevH0,
        nextAggregationData0PrevH1,
        nextAggregationData0SumAmt,

        nextAggregationData1PrevH0,
        nextAggregationData1PrevH1,
        nextAggregationData1SumAmt,

        isExpandingLeaves,

        withdrawalData0AddressBuff,
        withdrawalData0AmtBuff,

        withdrawalData1AddressBuff,
        withdrawalData1AmtBuff,

        isLastAggregationLevel,

        fundingPrevout,

        scriptExpander.toBuffer(),
        Buffer.from(cblockExpander, 'hex')
    ]

    expanderTx6.inputs[0].witnesses = witnesses
    

    return {
        txFunds: txFunds,
        nodeTxns: [
            expanderTx0,
            expanderTx1,
            expanderTx2,
        ],
        leafTxns: [
            expanderTx3,
            expanderTx4,
            expanderTx5,
            expanderTx6
        ]
    }
}