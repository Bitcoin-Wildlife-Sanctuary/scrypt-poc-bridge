// @ts-ignore
import btc = require('bitcore-lib-inquisition');
import { Tap } from '@cmdcode/tapscript'  // Requires node >= 19

import * as dotenv from 'dotenv';
dotenv.config();

import { expect, use } from 'chai'
import chaiAsPromised from 'chai-as-promised'
use(chaiAsPromised)

import { WithdrawalAggregator, WithdrawalData } from '../src/contracts/withdrawalAggregator'
import { Bridge } from '../src/contracts/bridge'
import { hash256, PubKey, Sha256, toByteString } from 'scrypt-ts';
import { DISABLE_KEYSPEND_PUBKEY, fetchP2WPKHUtxos, schnorrTrick } from './utils/txHelper';
import { myAddress, myPrivateKey, myPublicKey } from './utils/privateKey';


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
            PubKey(toByteString(pubkeyOperator.toString()))
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

        const txFunds = new btc.Transaction()
            .from(utxos)
            .to(myAddress, 1500)
            .to(myAddress, 1500)
            .to(myAddress, 1500)
            .to(myAddress, 1500)
            .to(myAddress, 1500)
            .to(myAddress, 1500)
            .to(myAddress, 1500)
            .to(myAddress, 1500)
            .change(myAddress)
            .feePerByte(2)
            .sign(myPrivateKey)

        console.log('txFee (serialized):', txFunds.uncheckedSerialize())
        console.log('')

        //////// Construct 4x leaf withdrawal request transactions. ////////
        const withdrawalDataList: WithdrawalData[] = []
        const withdrawalDataHashList: Sha256[] = []
        const ownProofTxns: btc.Transaction[] = []
        const leafTxns: btc.Transaction[] = []
        for (let i = 0; i < 4; i++) {
            const fundingUTXO0 = {
                address: myAddress.toString(),
                txId: txFunds.id,
                outputIndex: i,
                script: new btc.Script(myAddress),
                satoshis: txFunds.outputs[i].satoshis
            }

            // Create ownership proof txn.
            const ownProofTx = new btc.Transaction()
                .from(fundingUTXO0)
                .to(myAddress, 1100)

            ownProofTxns.push(ownProofTx)

            console.log(`Ownership proof TX ${i} (serialized):`, ownProofTx.uncheckedSerialize())
            console.log('')

            const ownProofUTXO = {
                address: myAddress.toString(),
                txId: ownProofTx.id,
                outputIndex: 0,
                script: new btc.Script(myAddress),
                satoshis: ownProofTx.outputs[0].satoshis
            }

            // Withdrawal information.
            const withdrawalAmount = 1500n
            const withdrwalData: WithdrawalData = {
                address: toByteString(myAddress.hashBuffer.toString('hex')) as Sha256,
                amount: withdrawalAmount
            }

            const withdrawalDataHash = WithdrawalAggregator.hashWithdrawalData(withdrwalData)
            const opRetScript = new btc.Script(`6a20${withdrawalDataHash}`)

            withdrawalDataList.push(withdrwalData)
            withdrawalDataHashList.push(withdrawalDataHash)

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

            console.log(`Leaf TX ${i} (serialized):`, leafTx.uncheckedSerialize())
            console.log('')
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
            outputIndex: 4,
            script: new btc.Script(myAddress),
            satoshis: txFunds.outputs[4].satoshis
        }

        const aggregateHash0 = hash256(withdrawalDataHashList[0] + withdrawalDataHashList[1])
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
                satoshis: 546,
                script: scriptAggregatorP2TR
            }))
            .addOutput(new btc.Transaction.Output({
                satoshis: 0,
                script: opRetScript
            }))
            .sign(myPrivateKey)

        let schnorrTrickDataIn0 = await schnorrTrick(aggregateTx0, tapleafAggregator, 0)
        let schnorrTrickDataIn1 = await schnorrTrick(aggregateTx0, tapleafAggregator, 1)

        let sigOperatorIn0 = btc.crypto.Schnorr.sign(seckeyOperator, schnorrTrickDataIn0.sighash.hash);
        let sigOperatorIn1 = btc.crypto.Schnorr.sign(seckeyOperator, schnorrTrickDataIn1.sighash.hash);

        let prevTx0Ver = Buffer.alloc(4)
        prevTx0Ver.writeUInt32LE(leafTxns[0].version)
        let prevTx0Locktime = Buffer.alloc(4)
        prevTx0Locktime.writeUInt32LE(leafTxns[0].nLockTime)
        let prevTx0InputFee = new btc.encoding.BufferWriter()
        leafTxns[0].inputs[0].toBufferWriter(prevTx0InputFee);
        let prevTx0ContractAmt = Buffer.alloc(8)
        prevTx0ContractAmt.writeUInt32LE(leafTxns[0].outputs[0].satoshis)
        let prevTx0ContractSPK = Buffer.concat([Buffer.from('22', 'hex'), scriptAggregatorP2TR.toBuffer()])
        let prevTx0HashData = withdrawalDataHashList[0]

        let prevTx1Ver = Buffer.alloc(4)
        prevTx1Ver.writeUInt32LE(leafTxns[1].version)
        let prevTx1Locktime = Buffer.alloc(4)
        prevTx1Locktime.writeUInt32LE(leafTxns[1].nLockTime)
        let prevTx1InputFee = new btc.encoding.BufferWriter()
        leafTxns[1].inputs[0].toBufferWriter(prevTx1InputFee);
        let prevTx1ContractAmt = Buffer.alloc(8)
        prevTx1ContractAmt.writeUInt32LE(leafTxns[1].outputs[0].satoshis)
        let prevTx1ContractSPK = Buffer.concat([Buffer.from('22', 'hex'), scriptAggregatorP2TR.toBuffer()])
        let prevTx1HashData = withdrawalDataHashList[1]

        let ownProofTx0Ver = Buffer.alloc(4)
        ownProofTx0Ver.writeUInt32LE(ownProofTxns[0].version)
        let ownProofTx0Locktime = Buffer.alloc(4)
        ownProofTx0Locktime.writeUInt32LE(ownProofTxns[0].nLockTime)
        let ownProofTx0Inputs = new btc.encoding.BufferWriter()
        ownProofTx0Inputs.writeVarintNum(ownProofTxns[0].inputs.length)
        ownProofTxns[0].inputs[0].toBufferWriter(ownProofTx0Inputs);
        let ownProofTx0OutputAmt = Buffer.alloc(8)
        ownProofTx0OutputAmt.writeUInt32LE(ownProofTxns[0].outputs[0].satoshis)
        let ownProofTx0OutputAddrP2WPKH = myAddress.hashBuffer

        let ownProofTx1Ver = Buffer.alloc(4)
        ownProofTx1Ver.writeUInt32LE(ownProofTxns[1].version)
        let ownProofTx1Locktime = Buffer.alloc(4)
        ownProofTx1Locktime.writeUInt32LE(ownProofTxns[1].nLockTime)
        let ownProofTx1Inputs = new btc.encoding.BufferWriter()
        ownProofTx1Inputs.writeVarintNum(ownProofTxns[1].inputs.length)
        ownProofTxns[1].inputs[0].toBufferWriter(ownProofTx1Inputs);
        let ownProofTx1OutputAmt = Buffer.alloc(8)
        ownProofTx1OutputAmt.writeUInt32LE(ownProofTxns[1].outputs[0].satoshis)
        let ownProofTx1OutputAddrP2WPKH = myAddress.hashBuffer

        let fundingPrevout = new btc.encoding.BufferWriter()
        fundingPrevout.writeReverse(aggregateTx0.inputs[2].prevTxId);
        fundingPrevout.writeInt32LE(aggregateTx0.inputs[2].outputIndex);

        let withdrawalData0AddressBuff = Buffer.from(withdrawalDataList[0].address, 'hex')
        let withdrawalData0AmtBuff = Buffer.alloc(2) // Bigint witnesses need to be minimally encoded! TODO: Do this automatically.
        withdrawalData0AmtBuff.writeInt16LE(Number(withdrawalDataList[0].amount))

        let withdrawalData1AddressBuff = Buffer.from(withdrawalDataList[1].address, 'hex')
        let withdrawalData1AmtBuff = Buffer.alloc(2)
        withdrawalData1AmtBuff.writeInt16LE(Number(withdrawalDataList[1].amount))

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

            Buffer.from('', 'hex'), // OP_0 - first public method chosen

            scriptAggregator.toBuffer(),
            Buffer.from(cblockAggregator, 'hex')
        ]
        aggregateTx0.inputs[0].witnesses = witnessesIn0

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

            Buffer.from('', 'hex'), // OP_0 - first public method chosen

            scriptAggregator.toBuffer(),
            Buffer.from(cblockAggregator, 'hex')
        ]
        aggregateTx0.inputs[1].witnesses = witnessesIn1

        console.log('Aggreate TX 0 (serialized):', aggregateTx0.uncheckedSerialize())
        console.log('')

        console.log(ownProofTxns[0].toBuffer(true).toString('hex'))

        // Run locally
        let interpreter = new btc.Script.Interpreter()
        let flags = btc.Script.Interpreter.SCRIPT_VERIFY_WITNESS | btc.Script.Interpreter.SCRIPT_VERIFY_TAPROOT | btc.Script.Interpreter.SCRIPT_VERIFY_DISCOURAGE_OP_SUCCESS
        let res = interpreter.verify(new btc.Script(''), leafTxns[0].outputs[0].script, aggregateTx0, 0, flags, witnessesIn0, leafTxns[0].outputs[0].satoshis)
        expect(res).to.be.true
        res = interpreter.verify(new btc.Script(''), leafTxns[1].outputs[0].script, aggregateTx0, 1, flags, witnessesIn1, leafTxns[1].outputs[0].satoshis)
        expect(res).to.be.true

        //////// Merge leaf 2 and leaf 3. ////////
        leafTx0UTXO = {
            txId: leafTxns[2].id,
            outputIndex: 0,
            script: scriptAggregatorP2TR,
            satoshis: leafTxns[2].outputs[0].satoshis
        }
        leafTx1UTXO = {
            txId: leafTxns[3].id,
            outputIndex: 0,
            script: scriptAggregatorP2TR,
            satoshis: leafTxns[3].outputs[0].satoshis
        }
        fundingUTXO = {
            address: myAddress.toString(),
            txId: txFunds.id,
            outputIndex: 5,
            script: new btc.Script(myAddress),
            satoshis: txFunds.outputs[5].satoshis
        }

        const aggregateHash1 = hash256(withdrawalDataHashList[2] + withdrawalDataHashList[3])
        opRetScript = new btc.Script(`6a20${aggregateHash1}`)

        const aggregateTx1 = new btc.Transaction()
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

        schnorrTrickDataIn0 = await schnorrTrick(aggregateTx1, tapleafAggregator, 0)
        schnorrTrickDataIn1 = await schnorrTrick(aggregateTx1, tapleafAggregator, 1)

        sigOperatorIn0 = btc.crypto.Schnorr.sign(seckeyOperator, schnorrTrickDataIn0.sighash.hash);
        sigOperatorIn1 = btc.crypto.Schnorr.sign(seckeyOperator, schnorrTrickDataIn1.sighash.hash);

        prevTx0Ver = Buffer.alloc(4)
        prevTx0Ver.writeUInt32LE(leafTxns[2].version)
        prevTx0Locktime = Buffer.alloc(4)
        prevTx0Locktime.writeUInt32LE(leafTxns[2].nLockTime)
        prevTx0InputFee = new btc.encoding.BufferWriter()
        leafTxns[2].inputs[0].toBufferWriter(prevTx0InputFee);
        prevTx0ContractAmt = Buffer.alloc(8)
        prevTx0ContractAmt.writeUInt32LE(leafTxns[2].outputs[0].satoshis)
        prevTx0ContractSPK = Buffer.concat([Buffer.from('22', 'hex'), scriptAggregatorP2TR.toBuffer()])
        prevTx0HashData = withdrawalDataHashList[2]

        prevTx1Ver = Buffer.alloc(4)
        prevTx1Ver.writeUInt32LE(leafTxns[3].version)
        prevTx1Locktime = Buffer.alloc(4)
        prevTx1Locktime.writeUInt32LE(leafTxns[3].nLockTime)
        prevTx1InputFee = new btc.encoding.BufferWriter()
        leafTxns[3].inputs[0].toBufferWriter(prevTx1InputFee);
        prevTx1ContractAmt = Buffer.alloc(8)
        prevTx1ContractAmt.writeUInt32LE(leafTxns[3].outputs[0].satoshis)
        prevTx1ContractSPK = Buffer.concat([Buffer.from('22', 'hex'), scriptAggregatorP2TR.toBuffer()])
        prevTx1HashData = withdrawalDataHashList[3]

        ownProofTx0Ver = Buffer.alloc(4)
        ownProofTx0Ver.writeUInt32LE(ownProofTxns[2].version)
        ownProofTx0Locktime = Buffer.alloc(4)
        ownProofTx0Locktime.writeUInt32LE(ownProofTxns[2].nLockTime)
        ownProofTx0Inputs = new btc.encoding.BufferWriter()
        ownProofTx0Inputs.writeVarintNum(ownProofTxns[2].inputs.length)
        ownProofTxns[2].inputs[0].toBufferWriter(ownProofTx0Inputs);
        ownProofTx0OutputAmt = Buffer.alloc(8)
        ownProofTx0OutputAmt.writeUInt32LE(ownProofTxns[2].outputs[0].satoshis)
        ownProofTx0OutputAddrP2WPKH = myAddress.hashBuffer

        ownProofTx1Ver = Buffer.alloc(4)
        ownProofTx1Ver.writeUInt32LE(ownProofTxns[3].version)
        ownProofTx1Locktime = Buffer.alloc(4)
        ownProofTx1Locktime.writeUInt32LE(ownProofTxns[3].nLockTime)
        ownProofTx1Inputs = new btc.encoding.BufferWriter()
        ownProofTx1Inputs.writeVarintNum(ownProofTxns[3].inputs.length)
        ownProofTxns[3].inputs[0].toBufferWriter(ownProofTx1Inputs);
        ownProofTx1OutputAmt = Buffer.alloc(8)
        ownProofTx1OutputAmt.writeUInt32LE(ownProofTxns[3].outputs[0].satoshis)
        ownProofTx1OutputAddrP2WPKH = myAddress.hashBuffer

        fundingPrevout = new btc.encoding.BufferWriter()
        fundingPrevout.writeReverse(aggregateTx1.inputs[2].prevTxId);
        fundingPrevout.writeInt32LE(aggregateTx1.inputs[2].outputIndex);

        withdrawalData0AddressBuff = Buffer.from(withdrawalDataList[2].address, 'hex')
        withdrawalData0AmtBuff = Buffer.alloc(2) // Bigint witnesses need to be minimally encoded! TODO: Do this automatically.
        withdrawalData0AmtBuff.writeInt16LE(Number(withdrawalDataList[2].amount))

        withdrawalData1AddressBuff = Buffer.from(withdrawalDataList[3].address, 'hex')
        withdrawalData1AmtBuff = Buffer.alloc(2)
        withdrawalData1AmtBuff.writeInt16LE(Number(withdrawalDataList[3].amount))

        witnessesIn0 = [
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

            Buffer.from('', 'hex'), // OP_0 - first public method chosen

            scriptAggregator.toBuffer(),
            Buffer.from(cblockAggregator, 'hex')
        ]
        aggregateTx1.inputs[0].witnesses = witnessesIn0

        witnessesIn1 = [
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

            Buffer.from('', 'hex'), // OP_0 - first public method chosen

            scriptAggregator.toBuffer(),
            Buffer.from(cblockAggregator, 'hex')
        ]
        aggregateTx1.inputs[1].witnesses = witnessesIn1

        console.log('Aggreate TX 1 (serialized):', aggregateTx1.uncheckedSerialize())
        console.log('')

        // Run locally
        interpreter = new btc.Script.Interpreter()
        flags = btc.Script.Interpreter.SCRIPT_VERIFY_WITNESS | btc.Script.Interpreter.SCRIPT_VERIFY_TAPROOT | btc.Script.Interpreter.SCRIPT_VERIFY_DISCOURAGE_OP_SUCCESS
        res = interpreter.verify(new btc.Script(''), leafTxns[2].outputs[0].script, aggregateTx1, 0, flags, witnessesIn0, leafTxns[2].outputs[0].satoshis)
        expect(res).to.be.true
        res = interpreter.verify(new btc.Script(''), leafTxns[3].outputs[0].script, aggregateTx1, 1, flags, witnessesIn1, leafTxns[3].outputs[0].satoshis)
        expect(res).to.be.true

        //////// Merge two aggregate nodes. ////////
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
        fundingUTXO = {
            address: myAddress.toString(),
            txId: txFunds.id,
            outputIndex: 7,
            script: new btc.Script(myAddress),
            satoshis: txFunds.outputs[7].satoshis
        }

        const aggregateHash2 = hash256(aggregateHash0 + aggregateHash1)
        opRetScript = new btc.Script(`6a20${aggregateHash2}`)

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

        schnorrTrickDataIn0 = await schnorrTrick(aggregateTx2, tapleafAggregator, 0)
        schnorrTrickDataIn1 = await schnorrTrick(aggregateTx2, tapleafAggregator, 1)

        sigOperatorIn0 = btc.crypto.Schnorr.sign(seckeyOperator, schnorrTrickDataIn0.sighash.hash);
        sigOperatorIn1 = btc.crypto.Schnorr.sign(seckeyOperator, schnorrTrickDataIn1.sighash.hash);

        prevTx0Ver = Buffer.alloc(4)
        prevTx0Ver.writeUInt32LE(aggregateTx0.version)
        prevTx0Locktime = Buffer.alloc(4)
        prevTx0Locktime.writeUInt32LE(aggregateTx0.nLockTime)
        let prevTx0InputContract0 = new btc.encoding.BufferWriter()
        aggregateTx0.inputs[0].toBufferWriter(prevTx0InputContract0);
        let prevTx0InputContract1 = new btc.encoding.BufferWriter()
        aggregateTx0.inputs[1].toBufferWriter(prevTx0InputContract1);
        prevTx0InputFee = new btc.encoding.BufferWriter()
        aggregateTx0.inputs[2].toBufferWriter(prevTx0InputFee);
        prevTx0ContractAmt = Buffer.alloc(8)
        prevTx0ContractAmt.writeUInt32LE(aggregateTx0.outputs[0].satoshis)
        prevTx0ContractSPK = Buffer.concat([Buffer.from('22', 'hex'), scriptAggregatorP2TR.toBuffer()])
        prevTx0HashData = aggregateHash0

        prevTx1Ver = Buffer.alloc(4)
        prevTx1Ver.writeUInt32LE(aggregateTx1.version)
        prevTx1Locktime = Buffer.alloc(4)
        prevTx1Locktime.writeUInt32LE(aggregateTx1.nLockTime)
        let prevTx1InputContract0 = new btc.encoding.BufferWriter()
        aggregateTx1.inputs[0].toBufferWriter(prevTx1InputContract0);
        let prevTx1InputContract1 = new btc.encoding.BufferWriter()
        aggregateTx1.inputs[1].toBufferWriter(prevTx1InputContract1);
        prevTx1InputFee = new btc.encoding.BufferWriter()
        aggregateTx1.inputs[2].toBufferWriter(prevTx1InputFee);
        prevTx1ContractAmt = Buffer.alloc(8)
        prevTx1ContractAmt.writeUInt32LE(aggregateTx1.outputs[0].satoshis)
        prevTx1ContractSPK = Buffer.concat([Buffer.from('22', 'hex'), scriptAggregatorP2TR.toBuffer()])
        prevTx1HashData = aggregateHash1

        fundingPrevout = new btc.encoding.BufferWriter()
        fundingPrevout.writeReverse(aggregateTx2.inputs[2].prevTxId);
        fundingPrevout.writeInt32LE(aggregateTx2.inputs[2].outputIndex);

        witnessesIn0 = [
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

            Buffer.from(''),
            Buffer.from(''),
            Buffer.from(''),
            Buffer.from(''),

            Buffer.from('', 'hex'), // OP_0 - first public method chosen

            scriptAggregator.toBuffer(),
            Buffer.from(cblockAggregator, 'hex')
        ]
        aggregateTx2.inputs[0].witnesses = witnessesIn0

        witnessesIn1 = [
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

            Buffer.from(''),
            Buffer.from(''),
            Buffer.from(''),
            Buffer.from(''),

            Buffer.from('', 'hex'), // OP_0 - first public method chosen

            scriptAggregator.toBuffer(),
            Buffer.from(cblockAggregator, 'hex')
        ]
        aggregateTx2.inputs[1].witnesses = witnessesIn1

        console.log('Aggreate TX 2 (serialized):', aggregateTx2.uncheckedSerialize())
        console.log('')

        // Run locally
        interpreter = new btc.Script.Interpreter()
        flags = btc.Script.Interpreter.SCRIPT_VERIFY_WITNESS | btc.Script.Interpreter.SCRIPT_VERIFY_TAPROOT | btc.Script.Interpreter.SCRIPT_VERIFY_DISCOURAGE_OP_SUCCESS
        res = interpreter.verify(new btc.Script(''), aggregateTx0.outputs[0].script, aggregateTx2, 0, flags, witnessesIn0, aggregateTx0.outputs[0].satoshis)
        expect(res).to.be.true
        res = interpreter.verify(new btc.Script(''), aggregateTx1.outputs[0].script, aggregateTx2, 1, flags, witnessesIn1, aggregateTx1.outputs[0].satoshis)
        expect(res).to.be.true

    })

})