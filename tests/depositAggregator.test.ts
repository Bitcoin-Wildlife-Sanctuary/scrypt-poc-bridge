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
import { hash256, PubKey, Sha256, SmartContract, toByteString } from 'scrypt-ts';
import { DISABLE_KEYSPEND_PUBKEY, fetchP2WPKHUtxos, getE, getSigHashSchnorr, schnorrTrick, splitSighashPreimage } from './utils/txHelper';
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
        
        const scriptAggregator = aggregator.lockingScript
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
            .to(myAddress, 1500)
            .to(myAddress, 1500)
            .to(myAddress, 1500)
            .change(myAddress)
            .feePerByte(2)
            .sign(myPrivateKey)

        console.log('txFee (serialized):', txFunds.uncheckedSerialize())

        //////// Construct 4x leaf deposit transactions. ////////
        const depositDataList: DepositData[] = []
        const depositDataHashList: Sha256[] = []
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

            depositDataList.push(depositData)
            depositDataHashList.push(depositDataHash)

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

        //////// Merge leaf 0 and leaf 1. ////////
        let leafTx0UTXO = {
            txId: leafTxns[0].id,
            outputIndex: 0,
            script: scriptAggregatorP2TR,
            satoshis: leafTxns[0].outputs[0].satoshis
        }
        let leafTx1UTXO = {
            txId: leafTxns[1].id,
            outputIndex: 0,
            script: scriptAggregatorP2TR,
            satoshis: leafTxns[1].outputs[0].satoshis
        }
        let fundingUTXO = {
            address: myAddress.toString(),
            txId: txFunds.id,
            outputIndex: 5,
            script: new btc.Script(myAddress),
            satoshis: txFunds.outputs[5].satoshis
        }

        const aggregateHash0 = hash256(depositDataHashList[0] + depositDataHashList[1])
        let opRetScript = new btc.Script(`6a20${aggregateHash0}`)

        const aggregateTx0 = new btc.Transaction()
            .from(
                [
                    leafTx0UTXO,
                    leafTx1UTXO,
                    fundingUTXO
                ]
            )
            .addOutput(new btc.Transaction.Output({
                satoshis: Number(
                    depositDataList[0].amount + depositDataList[1].amount
                ),
                script: scriptAggregatorP2TR
            }))
            .addOutput(new btc.Transaction.Output({
                satoshis: 0,
                script: opRetScript
            }))
            .sign(myPrivateKey)
        
        let schnorrTrickData = await schnorrTrick(aggregateTx0, tapleafAggregator, 0)
        
        let sigOperator = btc.crypto.Schnorr.sign(seckeyOperator, schnorrTrickData.sighash.hash);
        
        let prevTx0Ver = Buffer.alloc(4)
        prevTx0Ver.writeUInt32LE(leafTxns[0].version)
        let prevTx0Locktime = Buffer.alloc(4)
        prevTx0Locktime.writeUInt32LE(leafTxns[0].nLockTime)
        let prevTx0InputFee = new btc.encoding.BufferWriter()
        leafTxns[0].inputs[0].toBufferWriter(prevTx0InputFee);
        let prevTx0ContractAmt = Buffer.alloc(8)
        prevTx0ContractAmt.writeUInt32LE(leafTxns[0].outputs[0].satoshis)
        let prevTx0ContractSPK = Buffer.concat([Buffer.from('22', 'hex'), scriptAggregatorP2TR.toBuffer()])
        let prevTx0HashData = depositDataHashList[0]

        let prevTx1Ver = Buffer.alloc(4)
        prevTx1Ver.writeUInt32LE(leafTxns[1].version)
        let prevTx1Locktime = Buffer.alloc(4)
        prevTx1Locktime.writeUInt32LE(leafTxns[1].nLockTime)
        let prevTx1InputFee = new btc.encoding.BufferWriter()
        leafTxns[1].inputs[0].toBufferWriter(prevTx1InputFee);
        let prevTx1ContractAmt = Buffer.alloc(8)
        prevTx1ContractAmt.writeUInt32LE(leafTxns[1].outputs[0].satoshis)
        let prevTx1ContractSPK = Buffer.concat([Buffer.from('22', 'hex'), scriptAggregatorP2TR.toBuffer()])
        let prevTx1HashData = depositDataHashList[1]

        let fundingPrevout = new btc.encoding.BufferWriter()
        fundingPrevout.writeReverse(aggregateTx0.inputs[2].prevTxId);
        fundingPrevout.writeInt32LE(aggregateTx0.inputs[2].outputIndex);
        
        let depositData0AddressBuff = Buffer.from(depositDataList[0].address, 'hex')
        let depositData0AmtBuff = Buffer.alloc(8)
        depositData0AmtBuff.writeBigInt64LE(depositDataList[0].amount)

        let depositData1AddressBuff = Buffer.from(depositDataList[1].address, 'hex')
        let depositData1AmtBuff = Buffer.alloc(8)
        depositData1AmtBuff.writeBigInt64LE(depositDataList[1].amount)

        let witnessesIn0 = [
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
            Buffer.from(schnorrTrickData.eLastByte.toString(16), 'hex'),
            Buffer.from('01', 'hex'), // is prev tx leaf (true)
            sigOperator,
            
            prevTx0Ver,
            Buffer.from('', 'hex'),
            prevTx0InputFee.toBuffer(),
            prevTx0ContractAmt,
            prevTx0ContractSPK,
            Buffer.from(prevTx0HashData, 'hex'),
            prevTx0Locktime,
            
            prevTx1Ver,
            Buffer.from('', 'hex'),
            prevTx1InputFee.toBuffer(),
            prevTx1ContractAmt,
            prevTx1ContractSPK,
            Buffer.from(prevTx1HashData, 'hex'),
            prevTx1Locktime,

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
        aggregateTx0.inputs[0].witnesses = witnessesIn0
        
        let witnessesIn1 = [...witnessesIn0]
        witnessesIn1[32] = Buffer.from('', 'hex') // is first input (false)
        aggregateTx0.inputs[1].witnesses = witnessesIn1

        console.log('Aggreate TX 0 (serialized):', aggregateTx0.uncheckedSerialize())

        // Run locally
        let interpreter = new btc.Script.Interpreter()
        let flags = btc.Script.Interpreter.SCRIPT_VERIFY_WITNESS | btc.Script.Interpreter.SCRIPT_VERIFY_TAPROOT | btc.Script.Interpreter.SCRIPT_VERIFY_DISCOURAGE_OP_SUCCESS
        let res = interpreter.verify(new btc.Script(''), leafTxns[0].outputs[0].script, aggregateTx0, 0, flags, witnessesIn0, leafTxns[0].outputs[0].satoshis)
        expect(res).to.be.true
        res = interpreter.verify(new btc.Script(''), leafTxns[1].outputs[0].script, aggregateTx0, 1, flags, witnessesIn1, leafTxns[1].outputs[0].satoshis)
        expect(res).to.be.true



        // TODO: Merge leaf 2 and leaf 3.

        // TODO: Merge two aggregate nodes.

    })

})