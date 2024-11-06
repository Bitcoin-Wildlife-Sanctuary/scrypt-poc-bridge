// @ts-ignore
import btc = require('bitcore-lib-inquisition');
import { Tap } from '@cmdcode/tapscript'  // Requires node >= 19

import * as dotenv from 'dotenv';
dotenv.config();

import { expect, use } from 'chai'
import chaiAsPromised from 'chai-as-promised'
use(chaiAsPromised)

import { performDepositAggregation } from '../src/utils/depositAggregation'
import { DepositAggregator } from '../src/contracts/depositAggregator'
import { Bridge } from '../src/contracts/bridge'
import { Addr, PubKey, toByteString } from 'scrypt-ts';
import { DISABLE_KEYSPEND_PUBKEY, fetchP2WPKHUtxos } from '../src/utils/txHelper';
import { myAddress, myPrivateKey, myPublicKey } from '../src/utils/privateKey';


describe('Test SmartContract `DepositAggregator`', () => {
    let seckeyOperator
    let pubkeyOperator
    let addrOperator

    before(async () => {
        seckeyOperator = myPrivateKey
        pubkeyOperator = myPublicKey
        addrOperator = myAddress

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
        let operatorUTXOs = await fetchP2WPKHUtxos(addrOperator)
        if (operatorUTXOs.length === 0) {
            throw new Error(`No UTXO's for address: ${addrOperator.toString()}`)
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
        
        const txFee = 3000
        
        const aggregationRes = await performDepositAggregation(
            operatorUTXOs,
            deposits,
            txFee,
            scriptAggregatorP2TR,
            cblockAggregator,
            scriptAggregator,
            tapleafAggregator,
            seckeyOperator
        )

        // Run locally
        let interpreter = new btc.Script.Interpreter()
        let flags = btc.Script.Interpreter.SCRIPT_VERIFY_WITNESS | btc.Script.Interpreter.SCRIPT_VERIFY_TAPROOT | btc.Script.Interpreter.SCRIPT_VERIFY_DISCOURAGE_OP_SUCCESS

        let res = interpreter.verify(new btc.Script(''), aggregationRes.leafTxns[0].outputs[0].script, aggregationRes.aggregateTxns[0], 0, flags, aggregationRes.aggregateTxns[0].inputs[0].witnesses, aggregationRes.leafTxns[0].outputs[0].satoshis)
        expect(res).to.be.true
        res = interpreter.verify(new btc.Script(''), aggregationRes.leafTxns[1].outputs[0].script, aggregationRes.aggregateTxns[0], 1, flags, aggregationRes.aggregateTxns[0].inputs[1].witnesses, aggregationRes.leafTxns[1].outputs[0].satoshis)
        expect(res).to.be.true
        res = interpreter.verify(new btc.Script(''), aggregationRes.leafTxns[2].outputs[0].script, aggregationRes.aggregateTxns[1], 0, flags, aggregationRes.aggregateTxns[1].inputs[0].witnesses, aggregationRes.leafTxns[2].outputs[0].satoshis)
        expect(res).to.be.true
        res = interpreter.verify(new btc.Script(''), aggregationRes.leafTxns[3].outputs[0].script, aggregationRes.aggregateTxns[1], 1, flags, aggregationRes.aggregateTxns[1].inputs[1].witnesses, aggregationRes.leafTxns[3].outputs[0].satoshis)
        expect(res).to.be.true
        res = interpreter.verify(new btc.Script(''), aggregationRes.aggregateTxns[0].outputs[0].script, aggregationRes.aggregateTxns[2], 0, flags, aggregationRes.aggregateTxns[2].inputs[0].witnesses, aggregationRes.aggregateTxns[0].outputs[0].satoshis)
        expect(res).to.be.true
        res = interpreter.verify(new btc.Script(''), aggregationRes.aggregateTxns[1].outputs[0].script, aggregationRes.aggregateTxns[2], 1, flags, aggregationRes.aggregateTxns[2].inputs[1].witnesses, aggregationRes.aggregateTxns[1].outputs[0].satoshis)
        expect(res).to.be.true
    })

})