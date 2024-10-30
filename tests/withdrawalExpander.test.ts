// @ts-ignore
import btc = require('bitcore-lib-inquisition');
import { Tap } from "@cmdcode/tapscript"
import { expect } from "chai"
import { PubKey, toByteString, UTXO } from "scrypt-ts"
import { Bridge, AccountData } from "../src/contracts/bridge"
import { DepositAggregator } from "../src/contracts/depositAggregator"
import { GeneralUtils } from "../src/contracts/generalUtils"
import { MERKLE_PROOF_MAX_DEPTH } from "../src/contracts/merklePath"
import { AggregationData, WithdrawalAggregator } from "../src/contracts/withdrawalAggregator"
import { WithdrawalExpander } from "../src/contracts/withdrawalExpander"
import { initAccountsTree, performBridgeDeposit, performBridgeWithdrawal } from "./bridge.test"
import { performDepositAggregation } from "./depositAggregator.test"
import { myAddress, myPrivateKey, myPublicKey } from "./utils/privateKey"
import { DISABLE_KEYSPEND_PUBKEY, fetchP2WPKHUtxos, hexLEtoDecimal, schnorrTrick } from "./utils/txHelper"
import { performWithdrawalAggregation } from "./withdrawalAggregator.test"
import { AggregatorUtils } from '../src/contracts/aggregatorUtils';

describe('Test SmartContract `WithdrawalExpander`', () => {
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
            .to(myAddress, 3000)
            .to(myAddress, 3000)
            .to(myAddress, 3000)
            .to(myAddress, 3000)
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


        //////////////////////////////////////
        // Expansion of withdrawal results. //
        //////////////////////////////////////
        let expanderUTXO = {
            txId: bridgeWithdrawalRes.bridgeTx.id,
            outputIndex: 2,
            script: scriptExpanderP2TR,
            satoshis: bridgeWithdrawalRes.bridgeTx.outputs[2].satoshis
        }
        fundingUTXO = {
            address: myAddress.toString(),
            txId: txFundsBridge.id,
            outputIndex: 3,
            script: new btc.Script(myAddress),
            satoshis: txFundsBridge.outputs[3].satoshis
        }

        let splitAmt0 = hexLEtoDecimal(withdrawalAggregationRes.intermediateSums[0][0])
        let splitAmt1 = hexLEtoDecimal(withdrawalAggregationRes.intermediateSums[0][1])

        let aggregationHash = withdrawalAggregationRes.withdrawalTree.levels[2][0]

        opRetScript = new btc.Script(`6a20${aggregationHash}`)

        const expanderTx0 = new btc.Transaction()
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
            .sign(myPrivateKey)

        let schnorrTrickData = await schnorrTrick(expanderTx0, tapleafExpander, 0)
        let sigOperator = btc.crypto.Schnorr.sign(seckeyOperator, schnorrTrickData.sighash.hash);

        let isExpandingPrevTxFirstOutput = Buffer.from('', 'hex')
        let isPrevTxBridge = Buffer.from('01', 'hex')

        let prevTxBridgeVer = Buffer.alloc(4)
        prevTxBridgeVer.writeUInt32LE(bridgeWithdrawalRes.bridgeTx.version)
        let prevTxBridgeLocktime = Buffer.alloc(4)
        prevTxBridgeLocktime.writeUInt32LE(bridgeWithdrawalRes.bridgeTx.nLockTime)
        let prevTxBridgeInputsBW = new btc.encoding.BufferWriter()
        prevTxBridgeInputsBW.writeUInt8(bridgeWithdrawalRes.bridgeTx.inputs.length)
        for (const input of bridgeWithdrawalRes.bridgeTx.inputs) {
            input.toBufferWriter(prevTxBridgeInputsBW);
        }
        let prevTxBridgeInputs = prevTxBridgeInputsBW.toBuffer()
        let prevTxBridgeContractAmt = Buffer.alloc(2) // Bigint witnesses need to be minimally encoded! TODO: Do this automatically.
        prevTxBridgeContractAmt.writeInt16LE(bridgeWithdrawalRes.bridgeTx.outputs[0].satoshis)
        let prevTxBridgeContractSPK = Buffer.concat([Buffer.from('22', 'hex'), scriptBridgeP2TR.toBuffer()])
        let prevTxBridgeExpanderSPK = Buffer.concat([Buffer.from('22', 'hex'), scriptExpanderP2TR.toBuffer()])
        let prevTxBridgeAccountsRoot = Buffer.from(accountsTree.getRoot(), 'hex')
        let prevTxBridgeExpanderRoot = Buffer.from(bridgeWithdrawalRes.expanderRoot, 'hex')
        let prevTxBridgeExpanderAmt = Buffer.alloc(2) // Bigint witnesses need to be minimally encoded! TODO: Do this automatically.
        prevTxBridgeExpanderAmt.writeInt16LE(Number(bridgeWithdrawalRes.expanderAmt))
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

        let prevAggregationDataPrevH0 = Buffer.from(withdrawalAggregationRes.withdrawalTree.levels[1][0], 'hex')
        let prevAggregationDataPrevH1 = Buffer.from(withdrawalAggregationRes.withdrawalTree.levels[1][1], 'hex')
        let prevAggregationDataSumAmt = Buffer.alloc(2) // Bigint witnesses need to be minimally encoded! TODO: Do this automatically.
        prevAggregationDataSumAmt.writeInt16LE(Number(bridgeWithdrawalRes.expanderAmt))

        let currentAggregationDataPrevH0 = Buffer.from(withdrawalAggregationRes.withdrawalTree.levels[1][0], 'hex')
        let currentAggregationDataPrevH1 = Buffer.from(withdrawalAggregationRes.withdrawalTree.levels[1][1], 'hex')
        let currentAggregationDataSumAmt = Buffer.alloc(2) // Bigint witnesses need to be minimally encoded! TODO: Do this automatically.
        currentAggregationDataSumAmt.writeInt16LE(Number(bridgeWithdrawalRes.expanderAmt))

        let nextAggregationData0PrevH0 = Buffer.from(withdrawalAggregationRes.withdrawalTree.levels[0][0], 'hex')
        let nextAggregationData0PrevH1 = Buffer.from(withdrawalAggregationRes.withdrawalTree.levels[0][1], 'hex')
        let nextAggregationData0SumAmt = Buffer.alloc(2) // Bigint witnesses need to be minimally encoded! TODO: Do this automatically.
        nextAggregationData0SumAmt.writeInt16LE(splitAmt0)

        let nextAggregationData1PrevH0 = Buffer.from(withdrawalAggregationRes.withdrawalTree.levels[0][2], 'hex')
        let nextAggregationData1PrevH1 = Buffer.from(withdrawalAggregationRes.withdrawalTree.levels[0][3], 'hex')
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

        // Run locally
        let interpreter = new btc.Script.Interpreter()
        let flags = btc.Script.Interpreter.SCRIPT_VERIFY_WITNESS | btc.Script.Interpreter.SCRIPT_VERIFY_TAPROOT | btc.Script.Interpreter.SCRIPT_VERIFY_DISCOURAGE_OP_SUCCESS
        let res = interpreter.verify(new btc.Script(''), bridgeWithdrawalRes.bridgeTx.outputs[2].script, expanderTx0, 0, flags, expanderTx0.inputs[0].witnesses, bridgeWithdrawalRes.bridgeTx.outputs[2].satoshis)
        expect(res).to.be.true


        ////////////////////////////////
        // Expansion of first branch. //
        ////////////////////////////////
        expanderUTXO = {
            txId: expanderTx0.id,
            outputIndex: 0,
            script: scriptExpanderP2TR,
            satoshis: expanderTx0.outputs[0].satoshis
        }
        fundingUTXO = {
            address: myAddress.toString(),
            txId: txFundsBridge.id,
            outputIndex: 4,
            script: new btc.Script(myAddress),
            satoshis: txFundsBridge.outputs[4].satoshis
        }

        splitAmt0 = Number(withdrawalAggregationRes.withdrawalDataList[0].amount)
        splitAmt1 = Number(withdrawalAggregationRes.withdrawalDataList[1].amount)

        aggregationHash = withdrawalAggregationRes.withdrawalTree.levels[1][0]

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
            .sign(myPrivateKey)

        schnorrTrickData = await schnorrTrick(expanderTx1, tapleafExpander, 0)
        sigOperator = btc.crypto.Schnorr.sign(seckeyOperator, schnorrTrickData.sighash.hash);

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
        prevTxExpanderHashData = Buffer.from(bridgeWithdrawalRes.expanderRoot, 'hex')
        prevTxExpanderLocktime = Buffer.alloc(4)
        prevTxExpanderLocktime.writeUInt32LE(expanderTx0.nLockTime)

        prevAggregationDataPrevH0 = Buffer.from(withdrawalAggregationRes.withdrawalTree.levels[1][0], 'hex')
        prevAggregationDataPrevH1 = Buffer.from(withdrawalAggregationRes.withdrawalTree.levels[1][1], 'hex')
        prevAggregationDataSumAmt = Buffer.alloc(2) // Bigint witnesses need to be minimally encoded! TODO: Do this automatically.
        prevAggregationDataSumAmt.writeInt16LE(Number(bridgeWithdrawalRes.expanderAmt))

        currentAggregationDataPrevH0 = Buffer.from(withdrawalAggregationRes.withdrawalTree.levels[0][0], 'hex')
        currentAggregationDataPrevH1 = Buffer.from(withdrawalAggregationRes.withdrawalTree.levels[0][1], 'hex')
        currentAggregationDataSumAmt = Buffer.alloc(2) // Bigint witnesses need to be minimally encoded! TODO: Do this automatically.
        currentAggregationDataSumAmt.writeInt16LE(splitAmt0 + splitAmt1)

        nextAggregationData0PrevH0 = Buffer.from('', 'hex')
        nextAggregationData0PrevH1 = Buffer.from('', 'hex')
        nextAggregationData0SumAmt = Buffer.from('', 'hex')

        nextAggregationData1PrevH0 = Buffer.from('', 'hex')
        nextAggregationData1PrevH1 = Buffer.from('', 'hex')
        nextAggregationData1SumAmt = Buffer.from('', 'hex')

        isExpandingLeaves = Buffer.from('', 'hex')

        withdrawalData0AddressBuff = Buffer.from(withdrawalAggregationRes.withdrawalDataList[0].address, 'hex')
        withdrawalData0AmtBuff = Buffer.alloc(2) // Bigint witnesses need to be minimally encoded! TODO: Do this automatically.
        withdrawalData0AmtBuff.writeInt16LE(Number(withdrawalAggregationRes.withdrawalDataList[0].amount))

        withdrawalData1AddressBuff = Buffer.from(withdrawalAggregationRes.withdrawalDataList[1].address, 'hex')
        withdrawalData1AmtBuff = Buffer.alloc(2) // Bigint witnesses need to be minimally encoded! TODO: Do this automatically.
        withdrawalData1AmtBuff.writeInt16LE(Number(withdrawalAggregationRes.withdrawalDataList[1].amount))

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

        // Run locally
        res = interpreter.verify(new btc.Script(''), expanderTx0.outputs[0].script, expanderTx1, 0, flags, expanderTx1.inputs[0].witnesses, expanderTx0.outputs[0].satoshis)
        expect(res).to.be.true


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
            address: myAddress.toString(),
            txId: txFundsBridge.id,
            outputIndex: 5,
            script: new btc.Script(myAddress),
            satoshis: txFundsBridge.outputs[5].satoshis
        }

        splitAmt0 = Number(withdrawalAggregationRes.withdrawalDataList[2].amount)
        splitAmt1 = Number(withdrawalAggregationRes.withdrawalDataList[3].amount)

        aggregationHash = withdrawalAggregationRes.withdrawalTree.levels[1][1]

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
            .sign(myPrivateKey)

        schnorrTrickData = await schnorrTrick(expanderTx2, tapleafExpander, 0)
        sigOperator = btc.crypto.Schnorr.sign(seckeyOperator, schnorrTrickData.sighash.hash);

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
        prevTxExpanderHashData = Buffer.from(bridgeWithdrawalRes.expanderRoot, 'hex')
        prevTxExpanderLocktime = Buffer.alloc(4)
        prevTxExpanderLocktime.writeUInt32LE(expanderTx0.nLockTime)

        prevAggregationDataPrevH0 = Buffer.from(withdrawalAggregationRes.withdrawalTree.levels[1][0], 'hex')
        prevAggregationDataPrevH1 = Buffer.from(withdrawalAggregationRes.withdrawalTree.levels[1][1], 'hex')
        prevAggregationDataSumAmt = Buffer.alloc(2) // Bigint witnesses need to be minimally encoded! TODO: Do this automatically.
        prevAggregationDataSumAmt.writeInt16LE(Number(bridgeWithdrawalRes.expanderAmt))

        currentAggregationDataPrevH0 = Buffer.from(withdrawalAggregationRes.withdrawalTree.levels[0][2], 'hex')
        currentAggregationDataPrevH1 = Buffer.from(withdrawalAggregationRes.withdrawalTree.levels[0][3], 'hex')
        currentAggregationDataSumAmt = Buffer.alloc(2) // Bigint witnesses need to be minimally encoded! TODO: Do this automatically.
        currentAggregationDataSumAmt.writeInt16LE(splitAmt0 + splitAmt1)

        nextAggregationData0PrevH0 = Buffer.from('', 'hex')
        nextAggregationData0PrevH1 = Buffer.from('', 'hex')
        nextAggregationData0SumAmt = Buffer.from('', 'hex')

        nextAggregationData1PrevH0 = Buffer.from('', 'hex')
        nextAggregationData1PrevH1 = Buffer.from('', 'hex')
        nextAggregationData1SumAmt = Buffer.from('', 'hex')

        isExpandingLeaves = Buffer.from('', 'hex')

        withdrawalData0AddressBuff = Buffer.from(withdrawalAggregationRes.withdrawalDataList[2].address, 'hex')
        withdrawalData0AmtBuff = Buffer.alloc(2) // Bigint witnesses need to be minimally encoded! TODO: Do this automatically.
        withdrawalData0AmtBuff.writeInt16LE(Number(withdrawalAggregationRes.withdrawalDataList[2].amount))

        withdrawalData1AddressBuff = Buffer.from(withdrawalAggregationRes.withdrawalDataList[3].address, 'hex')
        withdrawalData1AmtBuff = Buffer.alloc(2) // Bigint witnesses need to be minimally encoded! TODO: Do this automatically.
        withdrawalData1AmtBuff.writeInt16LE(Number(withdrawalAggregationRes.withdrawalDataList[3].amount))

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

        // Run locally
        res = interpreter.verify(new btc.Script(''), expanderTx0.outputs[1].script, expanderTx2, 0, flags, expanderTx2.inputs[0].witnesses, expanderTx0.outputs[1].satoshis)
        expect(res).to.be.true


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
            address: myAddress.toString(),
            txId: txFundsBridge.id,
            outputIndex: 6,
            script: new btc.Script(myAddress),
            satoshis: txFundsBridge.outputs[6].satoshis
        }

        splitAmt0 = Number(withdrawalAggregationRes.withdrawalDataList[0].amount)
        splitAmt1 = Number(withdrawalAggregationRes.withdrawalDataList[1].amount)

        const expanderTx3 = new btc.Transaction()
            .from(
                [
                    expanderUTXO,
                    fundingUTXO
                ]
            )
            .addOutput(new btc.Transaction.Output({
                satoshis: splitAmt0,
                script: new btc.Script(myAddress)
            }))
            .sign(myPrivateKey)

        schnorrTrickData = await schnorrTrick(expanderTx3, tapleafExpander, 0)
        sigOperator = btc.crypto.Schnorr.sign(seckeyOperator, schnorrTrickData.sighash.hash);

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
        prevTxExpanderHashData = Buffer.from(withdrawalAggregationRes.withdrawalTree.levels[1][0], 'hex')
        prevTxExpanderLocktime = Buffer.alloc(4)
        prevTxExpanderLocktime.writeUInt32LE(expanderTx1.nLockTime)

        prevAggregationDataPrevH0 = Buffer.from(withdrawalAggregationRes.withdrawalTree.levels[0][0], 'hex')
        prevAggregationDataPrevH1 = Buffer.from(withdrawalAggregationRes.withdrawalTree.levels[0][1], 'hex')
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

        withdrawalData0AddressBuff = Buffer.from(withdrawalAggregationRes.withdrawalDataList[0].address, 'hex')
        withdrawalData0AmtBuff = Buffer.alloc(2) // Bigint witnesses need to be minimally encoded! TODO: Do this automatically.
        withdrawalData0AmtBuff.writeInt16LE(Number(withdrawalAggregationRes.withdrawalDataList[0].amount))

        withdrawalData1AddressBuff = Buffer.from(withdrawalAggregationRes.withdrawalDataList[1].address, 'hex')
        withdrawalData1AmtBuff = Buffer.alloc(2) // Bigint witnesses need to be minimally encoded! TODO: Do this automatically.
        withdrawalData1AmtBuff.writeInt16LE(Number(withdrawalAggregationRes.withdrawalDataList[1].amount))

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

        // Run locally
        res = interpreter.verify(new btc.Script(''), expanderTx1.outputs[0].script, expanderTx3, 0, flags, expanderTx3.inputs[0].witnesses, expanderTx1.outputs[0].satoshis)
        expect(res).to.be.true
        

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
            address: myAddress.toString(),
            txId: txFundsBridge.id,
            outputIndex: 7,
            script: new btc.Script(myAddress),
            satoshis: txFundsBridge.outputs[7].satoshis
        }

        splitAmt0 = Number(withdrawalAggregationRes.withdrawalDataList[0].amount)
        splitAmt1 = Number(withdrawalAggregationRes.withdrawalDataList[1].amount)

        const expanderTx4 = new btc.Transaction()
            .from(
                [
                    expanderUTXO,
                    fundingUTXO
                ]
            )
            .addOutput(new btc.Transaction.Output({
                satoshis: splitAmt1,
                script: new btc.Script(myAddress)
            }))
            .sign(myPrivateKey)

        schnorrTrickData = await schnorrTrick(expanderTx4, tapleafExpander, 0)
        sigOperator = btc.crypto.Schnorr.sign(seckeyOperator, schnorrTrickData.sighash.hash);

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
        prevTxExpanderHashData = Buffer.from(withdrawalAggregationRes.withdrawalTree.levels[1][0], 'hex')
        prevTxExpanderLocktime = Buffer.alloc(4)
        prevTxExpanderLocktime.writeUInt32LE(expanderTx1.nLockTime)

        prevAggregationDataPrevH0 = Buffer.from(withdrawalAggregationRes.withdrawalTree.levels[0][0], 'hex')
        prevAggregationDataPrevH1 = Buffer.from(withdrawalAggregationRes.withdrawalTree.levels[0][1], 'hex')
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

        withdrawalData0AddressBuff = Buffer.from(withdrawalAggregationRes.withdrawalDataList[0].address, 'hex')
        withdrawalData0AmtBuff = Buffer.alloc(2) // Bigint witnesses need to be minimally encoded! TODO: Do this automatically.
        withdrawalData0AmtBuff.writeInt16LE(Number(withdrawalAggregationRes.withdrawalDataList[0].amount))

        withdrawalData1AddressBuff = Buffer.from(withdrawalAggregationRes.withdrawalDataList[1].address, 'hex')
        withdrawalData1AmtBuff = Buffer.alloc(2) // Bigint witnesses need to be minimally encoded! TODO: Do this automatically.
        withdrawalData1AmtBuff.writeInt16LE(Number(withdrawalAggregationRes.withdrawalDataList[1].amount))

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

        // Run locally
        res = interpreter.verify(new btc.Script(''), expanderTx1.outputs[0].script, expanderTx4, 0, flags, expanderTx4.inputs[0].witnesses, expanderTx1.outputs[0].satoshis)
        expect(res).to.be.true


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
            address: myAddress.toString(),
            txId: txFundsBridge.id,
            outputIndex: 7,
            script: new btc.Script(myAddress),
            satoshis: txFundsBridge.outputs[7].satoshis
        }

        splitAmt0 = Number(withdrawalAggregationRes.withdrawalDataList[2].amount)
        splitAmt1 = Number(withdrawalAggregationRes.withdrawalDataList[3].amount)

        const expanderTx5 = new btc.Transaction()
            .from(
                [
                    expanderUTXO,
                    fundingUTXO
                ]
            )
            .addOutput(new btc.Transaction.Output({
                satoshis: splitAmt0,
                script: new btc.Script(myAddress)
            }))
            .sign(myPrivateKey)

        schnorrTrickData = await schnorrTrick(expanderTx5, tapleafExpander, 0)
        sigOperator = btc.crypto.Schnorr.sign(seckeyOperator, schnorrTrickData.sighash.hash);

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
        prevTxExpanderHashData = Buffer.from(withdrawalAggregationRes.withdrawalTree.levels[1][1], 'hex')
        prevTxExpanderLocktime = Buffer.alloc(4)
        prevTxExpanderLocktime.writeUInt32LE(expanderTx2.nLockTime)

        prevAggregationDataPrevH0 = Buffer.from(withdrawalAggregationRes.withdrawalTree.levels[0][2], 'hex')
        prevAggregationDataPrevH1 = Buffer.from(withdrawalAggregationRes.withdrawalTree.levels[0][3], 'hex')
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

        withdrawalData0AddressBuff = Buffer.from(withdrawalAggregationRes.withdrawalDataList[2].address, 'hex')
        withdrawalData0AmtBuff = Buffer.alloc(2) // Bigint witnesses need to be minimally encoded! TODO: Do this automatically.
        withdrawalData0AmtBuff.writeInt16LE(Number(withdrawalAggregationRes.withdrawalDataList[2].amount))

        withdrawalData1AddressBuff = Buffer.from(withdrawalAggregationRes.withdrawalDataList[3].address, 'hex')
        withdrawalData1AmtBuff = Buffer.alloc(2) // Bigint witnesses need to be minimally encoded! TODO: Do this automatically.
        withdrawalData1AmtBuff.writeInt16LE(Number(withdrawalAggregationRes.withdrawalDataList[3].amount))

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

        // Run locally
        res = interpreter.verify(new btc.Script(''), expanderTx2.outputs[0].script, expanderTx5, 0, flags, expanderTx5.inputs[0].witnesses, expanderTx2.outputs[0].satoshis)
        expect(res).to.be.true
        
        
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
            address: myAddress.toString(),
            txId: txFundsBridge.id,
            outputIndex: 8,
            script: new btc.Script(myAddress),
            satoshis: txFundsBridge.outputs[8].satoshis
        }

        splitAmt0 = Number(withdrawalAggregationRes.withdrawalDataList[2].amount)
        splitAmt1 = Number(withdrawalAggregationRes.withdrawalDataList[3].amount)

        const expanderTx6 = new btc.Transaction()
            .from(
                [
                    expanderUTXO,
                    fundingUTXO
                ]
            )
            .addOutput(new btc.Transaction.Output({
                satoshis: splitAmt1,
                script: new btc.Script(myAddress)
            }))
            .sign(myPrivateKey)

        schnorrTrickData = await schnorrTrick(expanderTx6, tapleafExpander, 0)
        sigOperator = btc.crypto.Schnorr.sign(seckeyOperator, schnorrTrickData.sighash.hash);

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
        prevTxExpanderHashData = Buffer.from(withdrawalAggregationRes.withdrawalTree.levels[1][1], 'hex')
        prevTxExpanderLocktime = Buffer.alloc(4)
        prevTxExpanderLocktime.writeUInt32LE(expanderTx2.nLockTime)

        prevAggregationDataPrevH0 = Buffer.from(withdrawalAggregationRes.withdrawalTree.levels[0][2], 'hex')
        prevAggregationDataPrevH1 = Buffer.from(withdrawalAggregationRes.withdrawalTree.levels[0][3], 'hex')
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

        withdrawalData0AddressBuff = Buffer.from(withdrawalAggregationRes.withdrawalDataList[2].address, 'hex')
        withdrawalData0AmtBuff = Buffer.alloc(2) // Bigint witnesses need to be minimally encoded! TODO: Do this automatically.
        withdrawalData0AmtBuff.writeInt16LE(Number(withdrawalAggregationRes.withdrawalDataList[2].amount))

        withdrawalData1AddressBuff = Buffer.from(withdrawalAggregationRes.withdrawalDataList[3].address, 'hex')
        withdrawalData1AmtBuff = Buffer.alloc(2) // Bigint witnesses need to be minimally encoded! TODO: Do this automatically.
        withdrawalData1AmtBuff.writeInt16LE(Number(withdrawalAggregationRes.withdrawalDataList[3].amount))

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

        // Run locally
        res = interpreter.verify(new btc.Script(''), expanderTx2.outputs[0].script, expanderTx6, 0, flags, expanderTx6.inputs[0].witnesses, expanderTx2.outputs[0].satoshis)
        expect(res).to.be.true

    })

})