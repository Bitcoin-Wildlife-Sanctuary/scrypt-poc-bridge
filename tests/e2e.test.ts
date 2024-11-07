// @ts-ignore
import btc = require('bitcore-lib-inquisition');
import { expect } from "chai"
import { Bridge } from "../src/contracts/bridge"
import { DepositAggregator } from "../src/contracts/depositAggregator"
import { WithdrawalAggregator } from "../src/contracts/withdrawalAggregator"
import { WithdrawalExpander } from "../src/contracts/withdrawalExpander"
import { deployBridge, performBridgeDeposit, performBridgeWithdrawal } from "../src/utils/bridge"
import { performDepositAggregation } from '../src/utils/depositAggregation'
import { myAddress, myPrivateKey, myPublicKey } from "../src/utils/privateKey"
import { createContractInstances, fetchP2WPKHUtxos } from "../src/utils/txHelper"
import { performWithdrawalAggregation } from '../src/utils/withrawalAggreagation'
import { DUST_AMOUNT } from 'bitcore-lib-inquisition/lib/transaction';
import { performWithdrawalExpansion } from '../src/utils/withdrawalExpansion'


describe('Test Full E2E Flow', () => {
    let seckeyOperator
    let pubkeyOperator
    let addrOperator

    before(async () => {
        seckeyOperator = myPrivateKey
        pubkeyOperator = myPublicKey
        addrOperator = myAddress

        await DepositAggregator.loadArtifact()
        await WithdrawalAggregator.loadArtifact()
        await WithdrawalExpander.loadArtifact()
        await Bridge.loadArtifact()
    })

    it('should pass', async () => {
        const contracts = createContractInstances(pubkeyOperator)

        let operatorUTXOs = await fetchP2WPKHUtxos(myAddress)
        if (operatorUTXOs.length === 0) {
            throw new Error(`No UTXO's for address: ${myAddress.toString()}`)
        }

        const depositAmounts = [1329n, 1400n, 1500n, 1888n]
        const txDepositFunds = new btc.Transaction()
            .from(operatorUTXOs)
            .to(myAddress, Number(depositAmounts[0]))
            .to(myAddress, Number(depositAmounts[1]))
            .to(myAddress, Number(depositAmounts[2]))
            .to(myAddress, Number(depositAmounts[3]))
            .change(addrOperator)
            .feePerByte(2)
            .sign(seckeyOperator)

        operatorUTXOs.length = 0
        operatorUTXOs.push(
            {
                address: addrOperator.toString(),
                txId: txDepositFunds.id,
                outputIndex: txDepositFunds.outputs.length - 1,
                script: new btc.Script(addrOperator),
                satoshis: txDepositFunds.outputs[txDepositFunds.outputs.length - 1].satoshis
            }
        )

        const deposits: any[] = []
        for (let i = 0; i < txDepositFunds.outputs.length - 1; i++) {
            deposits.push(
                {
                    from: {
                        txId: txDepositFunds.id,
                        outputIndex: i,
                        address: myAddress.toString(),
                        satoshis: txDepositFunds.outputs[i].satoshis
                    },
                    address: myAddress.toString()
                },
            )
        }

        const depositAggregationRes = await performDepositAggregation(
            operatorUTXOs,
            deposits,
            contracts.depositAggregator.scriptP2TR,
            contracts.depositAggregator.cblock,
            contracts.depositAggregator.script,
            contracts.depositAggregator.tapleaf,
            seckeyOperator,
            2
        )
        
        operatorUTXOs = depositAggregationRes.operatorUTXOs

        const withdrawalAmounts = [1000n, 800n, 700n, 997n]

        const txWithdrawalFunds = new btc.Transaction()
            .from(operatorUTXOs)
            .to(addrOperator, DUST_AMOUNT * 4)
            .to(addrOperator, DUST_AMOUNT * 4)
            .to(addrOperator, DUST_AMOUNT * 4)
            .to(addrOperator, DUST_AMOUNT * 4)
            .change(addrOperator)
            .feePerByte(2)
            .sign(seckeyOperator)

        operatorUTXOs.length = 0
        operatorUTXOs.push(
            {
                address: addrOperator.toString(),
                txId: txWithdrawalFunds.id,
                outputIndex: txWithdrawalFunds.outputs.length - 1,
                script: new btc.Script(addrOperator),
                satoshis: txWithdrawalFunds.outputs[txWithdrawalFunds.outputs.length - 1].satoshis
            }
        )

        const withdrawals: any[] = []
        for (let i = 0; i < txWithdrawalFunds.outputs.length - 1; i++) {
            const ownProofTx = new btc.Transaction()
            ownProofTx.from({
                txId: txWithdrawalFunds.id,
                outputIndex: i,
                address: addrOperator.toString(),
                satoshis: txWithdrawalFunds.outputs[i].satoshis,
                script: new btc.Script(addrOperator),
            })
            .to(addrOperator, DUST_AMOUNT)
            .sign(seckeyOperator)

            withdrawals.push(
                {
                    from: {
                        txId: ownProofTx.id,
                        outputIndex: 0,
                        address: addrOperator.toString(),
                        satoshis: ownProofTx.outputs[0].satoshis,
                        fullTx: ownProofTx.uncheckedSerialize()
                    },
                    address: addrOperator.toString(),
                    amount: Number(withdrawalAmounts[i])
                },
            )
        }
        
        const withdrawalAggregationRes = await performWithdrawalAggregation(
            operatorUTXOs,
            withdrawals,
            contracts.withdrawalAggregator.scriptP2TR,
            contracts.withdrawalAggregator.cblock,
            contracts.withdrawalAggregator.script,
            contracts.withdrawalAggregator.tapleaf,
            seckeyOperator,
            2
        )
        
        operatorUTXOs = withdrawalAggregationRes.operatorUTXOs

        ///////////////////
        // Deploy bridge //
        ///////////////////
        const deployRes = deployBridge(
            operatorUTXOs,
            contracts.bridge.scriptP2TR,
            contracts.depositAggregator.scriptP2TR,
            contracts.withdrawalAggregator.scriptP2TR,
            2
        )
        
        let bridgeData = deployRes.bridgeData
        let deployTx = deployRes.deployTx
        
        operatorUTXOs = deployRes.operatorUTXOs

        /////////////////////////////////
        // Deposit aggregation result. //
        /////////////////////////////////
        const bridgeDepositFee = 3000

        const bridgeDepositRes = await performBridgeDeposit(
            operatorUTXOs,
            bridgeDepositFee,
            deployTx,
            depositAggregationRes,
            bridgeData.accounts,
            bridgeData.accountsTree,
            contracts.bridge.scriptP2TR,
            contracts.depositAggregator.scriptP2TR,
            contracts.withdrawalAggregator.scriptP2TR,
            contracts.withdrawalExpander.scriptP2TR,
            contracts.bridge.tapleaf,
            contracts.depositAggregator.tapleaf,
            seckeyOperator,
            contracts.bridge.script,
            contracts.bridge.cblock,
            contracts.depositAggregator.script,
            contracts.depositAggregator.cblock,
        )

        ////////////////////////////////////
        // Withdrawal aggregation result. //
        ////////////////////////////////////
        const bridgeWithdrawalFee = 3000

        const bridgeWithdrawalRes = await performBridgeWithdrawal(
            operatorUTXOs,
            bridgeWithdrawalFee,
            bridgeDepositRes.bridgeTx,
            withdrawalAggregationRes,
            bridgeData.accounts,
            bridgeData.accountsTree,
            contracts.bridge.scriptP2TR,
            contracts.depositAggregator.scriptP2TR,
            contracts.withdrawalAggregator.scriptP2TR,
            contracts.withdrawalExpander.scriptP2TR,
            contracts.bridge.tapleaf,
            contracts.withdrawalAggregator.tapleaf,
            seckeyOperator,
            contracts.bridge.script,
            contracts.bridge.cblock,
            contracts.withdrawalAggregator.script,
            contracts.withdrawalAggregator.cblock,
        )

        //////////////////////////////////////
        // Expansion of withdrawal results. //
        //////////////////////////////////////

        const expanderTxFee = 3000

        const expansionRes = await performWithdrawalExpansion(
            operatorUTXOs,
            bridgeData.accountsTree,
            bridgeWithdrawalRes.bridgeTx,
            withdrawalAggregationRes.intermediateSums,
            withdrawalAggregationRes.withdrawalDataList,
            withdrawalAggregationRes.withdrawalTree,
            expanderTxFee,

            bridgeWithdrawalRes.expanderRoot,
            bridgeWithdrawalRes.expanderAmt,

            contracts.bridge.scriptP2TR,
            contracts.depositAggregator.scriptP2TR,
            contracts.withdrawalAggregator.scriptP2TR,

            contracts.withdrawalExpander.scriptP2TR,
            contracts.withdrawalExpander.script,
            contracts.withdrawalExpander.tapleaf,
            contracts.withdrawalExpander.cblock
        )

        // Run locally
        let interpreter = new btc.Script.Interpreter()
        let flags = btc.Script.Interpreter.SCRIPT_VERIFY_WITNESS | btc.Script.Interpreter.SCRIPT_VERIFY_TAPROOT | btc.Script.Interpreter.SCRIPT_VERIFY_DISCOURAGE_OP_SUCCESS

        let res = interpreter.verify(new btc.Script(''), depositAggregationRes.leafTxns[0].outputs[0].script, depositAggregationRes.aggregateTxns[0], 0, flags, depositAggregationRes.aggregateTxns[0].inputs[0].witnesses, depositAggregationRes.leafTxns[0].outputs[0].satoshis)
        expect(res).to.be.true
        res = interpreter.verify(new btc.Script(''), depositAggregationRes.leafTxns[1].outputs[0].script, depositAggregationRes.aggregateTxns[0], 1, flags, depositAggregationRes.aggregateTxns[0].inputs[1].witnesses, depositAggregationRes.leafTxns[1].outputs[0].satoshis)
        expect(res).to.be.true
        res = interpreter.verify(new btc.Script(''), depositAggregationRes.leafTxns[2].outputs[0].script, depositAggregationRes.aggregateTxns[1], 0, flags, depositAggregationRes.aggregateTxns[1].inputs[0].witnesses, depositAggregationRes.leafTxns[2].outputs[0].satoshis)
        expect(res).to.be.true
        res = interpreter.verify(new btc.Script(''), depositAggregationRes.leafTxns[3].outputs[0].script, depositAggregationRes.aggregateTxns[1], 1, flags, depositAggregationRes.aggregateTxns[1].inputs[1].witnesses, depositAggregationRes.leafTxns[3].outputs[0].satoshis)
        expect(res).to.be.true
        res = interpreter.verify(new btc.Script(''), depositAggregationRes.aggregateTxns[0].outputs[0].script, depositAggregationRes.aggregateTxns[2], 0, flags, depositAggregationRes.aggregateTxns[2].inputs[0].witnesses, depositAggregationRes.aggregateTxns[0].outputs[0].satoshis)
        expect(res).to.be.true
        res = interpreter.verify(new btc.Script(''), depositAggregationRes.aggregateTxns[1].outputs[0].script, depositAggregationRes.aggregateTxns[2], 1, flags, depositAggregationRes.aggregateTxns[2].inputs[1].witnesses, depositAggregationRes.aggregateTxns[1].outputs[0].satoshis)
        expect(res).to.be.true

        res = interpreter.verify(new btc.Script(''), withdrawalAggregationRes.leafTxns[0].outputs[0].script, withdrawalAggregationRes.aggregateTxns[0], 0, flags, withdrawalAggregationRes.aggregateTxns[0].inputs[0].witnesses, withdrawalAggregationRes.leafTxns[0].outputs[0].satoshis)
        expect(res).to.be.true
        res = interpreter.verify(new btc.Script(''), withdrawalAggregationRes.leafTxns[1].outputs[0].script, withdrawalAggregationRes.aggregateTxns[0], 1, flags, withdrawalAggregationRes.aggregateTxns[0].inputs[1].witnesses, withdrawalAggregationRes.leafTxns[1].outputs[0].satoshis)
        expect(res).to.be.true
        res = interpreter.verify(new btc.Script(''), withdrawalAggregationRes.leafTxns[2].outputs[0].script, withdrawalAggregationRes.aggregateTxns[1], 0, flags, withdrawalAggregationRes.aggregateTxns[1].inputs[0].witnesses, withdrawalAggregationRes.leafTxns[2].outputs[0].satoshis)
        expect(res).to.be.true
        res = interpreter.verify(new btc.Script(''), withdrawalAggregationRes.leafTxns[3].outputs[0].script, withdrawalAggregationRes.aggregateTxns[1], 1, flags, withdrawalAggregationRes.aggregateTxns[1].inputs[1].witnesses, withdrawalAggregationRes.leafTxns[3].outputs[0].satoshis)
        expect(res).to.be.true
        res = interpreter.verify(new btc.Script(''), withdrawalAggregationRes.aggregateTxns[0].outputs[0].script, withdrawalAggregationRes.aggregateTxns[2], 0, flags, withdrawalAggregationRes.aggregateTxns[2].inputs[0].witnesses, withdrawalAggregationRes.aggregateTxns[0].outputs[0].satoshis)
        expect(res).to.be.true
        res = interpreter.verify(new btc.Script(''), withdrawalAggregationRes.aggregateTxns[1].outputs[0].script, withdrawalAggregationRes.aggregateTxns[2], 1, flags, withdrawalAggregationRes.aggregateTxns[2].inputs[1].witnesses, withdrawalAggregationRes.aggregateTxns[1].outputs[0].satoshis)
        expect(res).to.be.true
        
        res = interpreter.verify(new btc.Script(''), deployTx.outputs[0].script, bridgeDepositRes.bridgeTx, 0, flags, bridgeDepositRes.bridgeTx.inputs[0].witnesses, deployTx.outputs[0].satoshis)
        expect(res).to.be.true
        res = interpreter.verify(new btc.Script(''), depositAggregationRes.aggregateTxns[2].outputs[0].script, bridgeDepositRes.bridgeTx, 1, flags, bridgeDepositRes.bridgeTx.inputs[1].witnesses, depositAggregationRes.aggregateTxns[2].outputs[0].satoshis)
        expect(res).to.be.true
        
        res = interpreter.verify(new btc.Script(''), bridgeDepositRes.bridgeTx.outputs[0].script, bridgeWithdrawalRes.bridgeTx, 0, flags, bridgeWithdrawalRes.bridgeTx.inputs[0].witnesses, bridgeDepositRes.bridgeTx.outputs[0].satoshis)
        expect(res).to.be.true
        res = interpreter.verify(new btc.Script(''), withdrawalAggregationRes.aggregateTxns[2].outputs[0].script, bridgeWithdrawalRes.bridgeTx, 1, flags, bridgeWithdrawalRes.bridgeTx.inputs[1].witnesses, withdrawalAggregationRes.aggregateTxns[2].outputs[0].satoshis)
        expect(res).to.be.true

        res = interpreter.verify(new btc.Script(''), bridgeWithdrawalRes.bridgeTx.outputs[2].script, expansionRes.nodeTxns[0], 0, flags, expansionRes.nodeTxns[0].inputs[0].witnesses, bridgeWithdrawalRes.bridgeTx.outputs[2].satoshis)
        expect(res).to.be.true
        res = interpreter.verify(new btc.Script(''), expansionRes.nodeTxns[0].outputs[0].script, expansionRes.nodeTxns[1], 0, flags, expansionRes.nodeTxns[1].inputs[0].witnesses, expansionRes.nodeTxns[0].outputs[0].satoshis)
        expect(res).to.be.true
        res = interpreter.verify(new btc.Script(''), expansionRes.nodeTxns[0].outputs[1].script, expansionRes.nodeTxns[2], 0, flags, expansionRes.nodeTxns[2].inputs[0].witnesses, expansionRes.nodeTxns[0].outputs[1].satoshis)
        expect(res).to.be.true
        res = interpreter.verify(new btc.Script(''), expansionRes.nodeTxns[1].outputs[0].script, expansionRes.leafTxns[0], 0, flags, expansionRes.leafTxns[0].inputs[0].witnesses, expansionRes.nodeTxns[1].outputs[0].satoshis)
        expect(res).to.be.true
        res = interpreter.verify(new btc.Script(''), expansionRes.nodeTxns[1].outputs[0].script, expansionRes.leafTxns[1], 0, flags, expansionRes.leafTxns[1].inputs[0].witnesses, expansionRes.nodeTxns[1].outputs[0].satoshis)
        expect(res).to.be.true
        res = interpreter.verify(new btc.Script(''), expansionRes.nodeTxns[2].outputs[0].script, expansionRes.leafTxns[2], 0, flags, expansionRes.leafTxns[2].inputs[0].witnesses, expansionRes.nodeTxns[2].outputs[0].satoshis)
        expect(res).to.be.true
        res = interpreter.verify(new btc.Script(''), expansionRes.nodeTxns[2].outputs[0].script, expansionRes.leafTxns[3], 0, flags, expansionRes.leafTxns[3].inputs[0].witnesses, expansionRes.nodeTxns[2].outputs[0].satoshis)
        expect(res).to.be.true
    })

})