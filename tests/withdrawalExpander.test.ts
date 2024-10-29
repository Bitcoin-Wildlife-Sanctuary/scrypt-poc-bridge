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
        let prevTxBridgeInputs = new btc.encoding.BufferWriter()
        prevTxBridgeInputs.writeUInt8(bridgeWithdrawalRes.bridgeTx.inputs.length)
        for (const input of bridgeWithdrawalRes.bridgeTx.inputs) {
            input.toBufferWriter(prevTxBridgeInputs);
        }
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

        let fundingPrevout = new btc.encoding.BufferWriter()
        fundingPrevout.writeReverse(expanderTx0.inputs[1].prevTxId);
        fundingPrevout.writeInt32LE(expanderTx0.inputs[1].outputIndex);

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
            prevTxBridgeInputs.toBuffer(),
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

            fundingPrevout.toBuffer(),

            scriptExpander.toBuffer(),
            Buffer.from(cblockExpander, 'hex')
        ]

        expanderTx0.inputs[0].witnesses = witnesses
        
        // Run locally
        let interpreter = new btc.Script.Interpreter()
        let flags = btc.Script.Interpreter.SCRIPT_VERIFY_WITNESS | btc.Script.Interpreter.SCRIPT_VERIFY_TAPROOT | btc.Script.Interpreter.SCRIPT_VERIFY_DISCOURAGE_OP_SUCCESS
        let res = interpreter.verify(new btc.Script(''), bridgeWithdrawalRes.bridgeTx.outputs[2].script, expanderTx0, 0, flags, expanderTx0.inputs[0].witnesses, bridgeWithdrawalRes.bridgeTx.outputs[2].satoshis)
        expect(res).to.be.true

    })

})