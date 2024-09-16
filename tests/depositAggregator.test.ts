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
import { PubKey, Sha256, SmartContract, toByteString } from 'scrypt-ts';
import { DISABLE_KEYSPEND_PUBKEY, fetchP2WPKHUtxos, getE, getSigHashSchnorr, splitSighashPreimage } from './utils/txHelper';
import { myAddress, myPrivateKey, myPublicKey } from './utils/privateKey';


describe('Test SmartContract `DepositAggregator`', () => {
    let seckeyOperator
    let pubkeyOperator
    let addrP2WPKHOperator

    before(async () => {
        seckeyOperator = myPrivateKey
        pubkeyOperator = myPublicKey
        addrP2WPKHOperator = myAddress

        await DepositAggregator.loadArtifact()
        await Bridge.loadArtifact()
    })

    it('should pass', async () => {
        // Create Bridge instance to get SPK which is used in DepositAggregators constructor.
        const bridge = new Bridge(
            PubKey(toByteString(pubkeyOperator.toString()))
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
        const scriptAggregator = bridge.lockingScript
        const tapleafAggregator = Tap.encodeScript(scriptAggregator.toBuffer())

        const [tpubkeyAggregator, cblockAggregator] = Tap.getPubKey(DISABLE_KEYSPEND_PUBKEY, { target: tapleafAggregator })
        const scriptAggregatorP2TR = new btc.Script(`OP_1 32 0x${tpubkeyAggregator}}`)

        // Create transactions used to fund our test txns.
        let utxos = await fetchP2WPKHUtxos(myAddress)
        if (utxos.length === 0) {
            throw new Error(`No UTXO's for address: ${myAddress.toString()}`)
        }

        const txFunds = new btc.Transaction()
            .from(utxos)
            .to(myAddress, 3000)
            .to(myAddress, 3000)
            .to(myAddress, 3000)
            .to(myAddress, 3000)
            .change(myAddress)
            .feePerByte(2)
            .sign(myPrivateKey)

        console.log('txFee (serialized):', txFunds.uncheckedSerialize())

        // Construct 4x leaf deposit transactions.
        const leafTxns: btc.Transaction[] = []
        for (let i = 0; i < 4; i++) {
            // UTXO where our leaf tx gets the needed funds from.
            const fundingUTXO = {
                address: myAddress.toString(),
                txId: txFunds.id,
                outputIndex: i,
                script: new btc.Script(myAddress),
                satoshis: txFunds.outputs[i].satoshis
            }
            
            // Deposit information.
            const depositAmount = 1500n
            const depositData: DepositData = {
                address: toByteString(myAddress.toBuffer().toString('hex')) as Sha256,
                amount: depositAmount
            }
            const depositDataHash = DepositAggregator.hashDepositData(depositData)
            const opRetScript = new btc.Script(`6a20${depositDataHash}`)

            // Construct leaf txn.
            const leafTx = new btc.Transaction()
                .from(fundingUTXO)
                .addOutput(new btc.Transaction.Output({
                    satoshis: Number(depositAmount),
                    script: scriptAggregatorP2TR
                }))
                .addOutput(new btc.Transaction.Output({
                    satoshis: 0,
                    script: opRetScript
                }))
                .sign(myPrivateKey)

            leafTxns.push(leafTx)
        }
        
        console.log(leafTxns)

    })

})