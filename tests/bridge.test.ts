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
import { ByteString, PubKey, toByteString, UTXO } from 'scrypt-ts';
import { DISABLE_KEYSPEND_PUBKEY, fetchP2WPKHUtxos, schnorrTrick } from '../src/utils/txHelper';
import { myAddress, myPrivateKey, myPublicKey } from '../src/utils/privateKey';
import { WithdrawalAggregator, WithdrawalData } from '../src/contracts/withdrawalAggregator';
import { performDepositAggregation } from '../src/utils/depositAggregation'
import { MERKLE_PROOF_MAX_DEPTH, MerkleProof, NodePos } from '../src/contracts/merklePath';
import { GeneralUtils } from '../src/contracts/generalUtils';
import { buildMerkleTree, MerkleTree } from '../src/utils/merkleTree';
import { performWithdrawalAggregation } from '../src/utils/withrawalAggreagation';
import { DUST_AMOUNT } from 'bitcore-lib-inquisition/lib/transaction';
import { initAccountsTree, performBridgeDeposit, performBridgeWithdrawal } from '../src/utils/bridge'


describe('Test SmartContract `Bridge`', () => {
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
        const depositTxFee = 3000

        const depositAggregationRes = await performDepositAggregation(
            operatorUTXOs, deposits, depositTxFee, scriptDepositAggregatorP2TR, cblockDepositAggregator,
            scriptDepositAggregator, tapleafDepositAggregator, seckeyOperator
        )

        const withdrawalAmounts = [1000n, 800n, 700n, 998n]
        
        const txWithdrawalFunds = new btc.Transaction()
            .from(operatorUTXOs)
            .to(myAddress, DUST_AMOUNT)
            .to(myAddress, DUST_AMOUNT)
            .to(myAddress, DUST_AMOUNT)
            .to(myAddress, DUST_AMOUNT)
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
            withdrawals.push(
                {
                    from: {
                        txId: txWithdrawalFunds.id,
                        outputIndex: i,
                        address: myAddress.toString(),
                        satoshis: txWithdrawalFunds.outputs[i].satoshis
                    },
                    address: myAddress.toString(),
                    amount: Number(withdrawalAmounts[i])
                },
            )
        }
        
        const withdrawalTxFee = 3000

        const withdrawalAggregationRes = await performWithdrawalAggregation(
            operatorUTXOs, withdrawals, withdrawalTxFee, scriptWithdrawalAggregatorP2TR, cblockWithdrawalAggregator,
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
                operatorUTXOs
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
        res = interpreter.verify(new btc.Script(''), depositAggregationRes.aggregateTxns[2].outputs[0].script, bridgeDepositRes.bridgeTx, 1, flags, bridgeDepositRes.bridgeTx.inputs[1].witnesses, depositAggregationRes.aggregateTxns[2].outputs[0].satoshis)
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
        res = interpreter.verify(new btc.Script(''), withdrawalAggregationRes.aggregateTxns[2].outputs[0].script, bridgeWithdrawalRes.bridgeTx, 1, flags, bridgeWithdrawalRes.bridgeTx.inputs[1].witnesses, withdrawalAggregationRes.aggregateTxns[2].outputs[0].satoshis)
        expect(res).to.be.true
    })

})