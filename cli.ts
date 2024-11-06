#!/usr/bin/env ts-node

import * as fs from 'fs';
import path from 'path';
import { Command } from 'commander';
import { version } from './package.json';
import { Bridge } from './src/contracts/bridge'
import { myAddress, myPrivateKey, myPublicKey } from './src/utils/privateKey';
import { DepositAggregator } from './src/contracts/depositAggregator';
import { PubKey, toByteString } from 'scrypt-ts';
// @ts-ignore
import btc = require('bitcore-lib-inquisition');
import { Tap } from '@cmdcode/tapscript'  // Requires node >= 19
import { DISABLE_KEYSPEND_PUBKEY, fetchP2WPKHUtxos } from './src/utils/txHelper';
import { WithdrawalAggregator } from './src/contracts/withdrawalAggregator';
import { WithdrawalExpander } from './src/contracts/withdrawalExpander';
import ARTIFACT_DEPOSIT_AGGREGATOR from './artifacts/depositAggregator.json'
import ARTIFACT_WITHDRAWAL_AGGREGATOR from './artifacts/withdrawalAggregator.json'
import ARTIFACT_BRIDGE from './artifacts/bridge.json'
import ARTIFACT_WITHDRAWAL_EXPANDER from './artifacts/withdrawalExpander.json'
import { performDepositAggregation } from './src/utils/depositAggregation';
import { performWithdrawalAggregation } from './src/utils/withrawalAggreagation';

const program = new Command();

async function loadContractsInfo(
  pubkeyOperator: btc.PublicKey
) {
  await DepositAggregator.loadArtifact(ARTIFACT_DEPOSIT_AGGREGATOR)
  await WithdrawalAggregator.loadArtifact(ARTIFACT_WITHDRAWAL_AGGREGATOR)
  await Bridge.loadArtifact(ARTIFACT_BRIDGE)
  await WithdrawalExpander.loadArtifact(ARTIFACT_WITHDRAWAL_EXPANDER)

  const expander = new WithdrawalExpander(
    PubKey(toByteString(pubkeyOperator.toString()))
  )

  const scriptExpander = expander.lockingScript
  const tapleafExpander = Tap.encodeScript(scriptExpander.toBuffer())

  const [tpubkeyExpander, cblockExpander] = Tap.getPubKey(DISABLE_KEYSPEND_PUBKEY, { target: tapleafExpander })
  const scriptExpanderP2TR = new btc.Script(`OP_1 32 0x${tpubkeyExpander}}`)


  const bridge = new Bridge(
    PubKey(toByteString(pubkeyOperator.toString())),
    toByteString('22' + scriptExpanderP2TR.toBuffer().toString('hex'))
  )

  const scriptBridge = bridge.lockingScript
  const tapleafBridge = Tap.encodeScript(scriptBridge.toBuffer())

  const [tpubkeyBridge, cblockBridge] = Tap.getPubKey(DISABLE_KEYSPEND_PUBKEY, { target: tapleafBridge })
  const scriptBridgeP2TR = new btc.Script(`OP_1 32 0x${tpubkeyBridge}}`)


  const depositAggregator = new DepositAggregator(
    PubKey(toByteString(pubkeyOperator.toString())),
    toByteString(scriptBridgeP2TR.toBuffer().toString('hex'))
  )

  const scriptDepositAggregator = depositAggregator.lockingScript
  const tapleafDepositAggregator = Tap.encodeScript(scriptDepositAggregator.toBuffer())

  const [tpubkeyDepositAggregator, cblockDepositAggregator] = Tap.getPubKey(DISABLE_KEYSPEND_PUBKEY, { target: tapleafDepositAggregator })
  const scriptDepositAggregatorP2TR = new btc.Script(`OP_1 32 0x${tpubkeyDepositAggregator}}`)


  const withdrawalAggregator = new WithdrawalAggregator(
    PubKey(toByteString(pubkeyOperator.toString())),
    toByteString(scriptBridgeP2TR.toBuffer().toString('hex'))
  )

  const scriptWithdrawalAggregator = withdrawalAggregator.lockingScript
  const tapleafWithdrawalAggregator = Tap.encodeScript(scriptWithdrawalAggregator.toBuffer())

  const [tpubkeyWithdrawalAggregator, cblockWithdrawalAggregator] = Tap.getPubKey(DISABLE_KEYSPEND_PUBKEY, { target: tapleafWithdrawalAggregator })
  const scriptWithdrawalAggregatorP2TR = new btc.Script(`OP_1 32 0x${tpubkeyWithdrawalAggregator}}`)

  return {
    depositAggregator: {
      instance: depositAggregator,
      script: scriptDepositAggregator,
      scriptP2TR: scriptDepositAggregatorP2TR,
      tapleaf: tapleafDepositAggregator,
      tpubkey: tpubkeyDepositAggregator,
      cblock: cblockDepositAggregator
    },
    withdrawalAggregator: {
      instance: withdrawalAggregator,
      script: scriptWithdrawalAggregator,
      scriptP2TR: scriptWithdrawalAggregatorP2TR,
      tapleaf: tapleafWithdrawalAggregator,
      tpubkey: tpubkeyWithdrawalAggregator,
      cblock: cblockWithdrawalAggregator
    },
    bridge: {
      instance: bridge,
      script: scriptBridge,
      scriptP2TR: scriptBridgeP2TR,
      tapleaf: tapleafBridge,
      tpubkey: tpubkeyBridge,
      cblock: cblockBridge
    },
    withdrawalExpander: {
      instance: expander,
      script: scriptExpander,
      scriptP2TR: scriptExpanderP2TR,
      tapleaf: tapleafExpander,
      tpubkey: tpubkeyExpander,
      cblock: cblockExpander
    }
  }
}

async function aggregateDeposits(inputFile: string, options: { output: string }) {
  const { output } = options;

  // Read and parse the input JSON file
  const inputFilePath = path.resolve(inputFile);
  const deposits = JSON.parse(fs.readFileSync(inputFilePath, 'utf-8'));

  const seckeyOperator = myPrivateKey
  const pubkeyOperator = myPublicKey
  const addrOperator = myAddress

  const contractsInfo = await loadContractsInfo(pubkeyOperator)

  // Create transactions used to fund our test txns.
  let operatorUTXOs = await fetchP2WPKHUtxos(addrOperator)
  if (operatorUTXOs.length === 0) {
    throw new Error(`No UTXO's for address: ${seckeyOperator.toString()}`)
  }

  const txFee = 3000 // TODO: dynamicly adjusted

  const aggregationRes = await performDepositAggregation(
    operatorUTXOs,
    deposits,
    txFee,
    contractsInfo.depositAggregator.scriptP2TR,
    contractsInfo.depositAggregator.cblock,
    contractsInfo.depositAggregator.script,
    contractsInfo.depositAggregator.tapleaf,
    seckeyOperator
  )
  
  // TODO: Evaluate txns locally?
  
  console.log(aggregationRes.leafTxns[0].vsize)
  console.log(aggregationRes.aggregateTxns[0].vsize)

  const res = {
    depositsData: aggregationRes.depositDataList,
    depositTree: aggregationRes.depositTree,
    txFunds: aggregationRes.txFunds.uncheckedSerialize(),
    leafTxns: aggregationRes.leafTxns.map((leafTx) => leafTx.uncheckedSerialize()),
    aggregateTxns: aggregationRes.aggregateTxns.map((aggregateTx) => aggregateTx.uncheckedSerialize())
  }

  // Resolve output file path with default if not provided
  const outputFilePath = path.resolve(output);
  fs.writeFileSync(outputFilePath, JSON.stringify(res, null, 2));
  console.log(`Aggregation results saved to ${outputFilePath}`);
}

async function aggregateWithdrawals(inputFile: string, options: { output: string }) {
  const { output } = options;

  // Read and parse the input JSON file
  const inputFilePath = path.resolve(inputFile);
  const withdrawals = JSON.parse(fs.readFileSync(inputFilePath, 'utf-8'));

  const seckeyOperator = myPrivateKey
  const pubkeyOperator = myPublicKey
  const addrOperator = myAddress

  const contractsInfo = await loadContractsInfo(pubkeyOperator)

  // Create transactions used to fund our test txns.
  let operatorUTXOs = await fetchP2WPKHUtxos(addrOperator)
  if (operatorUTXOs.length === 0) {
    throw new Error(`No UTXO's for address: ${seckeyOperator.toString()}`)
  }

  const txFee = 3000

  const aggregationRes = await performWithdrawalAggregation(
    operatorUTXOs,
    withdrawals,
    txFee,
    contractsInfo.depositAggregator.scriptP2TR,
    contractsInfo.depositAggregator.cblock,
    contractsInfo.depositAggregator.script,
    contractsInfo.depositAggregator.tapleaf,
    seckeyOperator
  )

  const res = {
    withdrawalsData: aggregationRes.withdrawalDataList,
    withdrawalTree: aggregationRes.withdrawalTree,
    txFunds: aggregationRes.txFunds.uncheckedSerialize(),
    leafTxns: aggregationRes.leafTxns.map((leafTx) => leafTx.uncheckedSerialize()),
    aggregateTxns: aggregationRes.aggregateTxns.map((aggregateTx) => aggregateTx.uncheckedSerialize())
  }

  // Resolve output file path with default if not provided
  const outputFilePath = path.resolve(output);
  fs.writeFileSync(outputFilePath, JSON.stringify(res, null, 2));
  console.log(`Aggregation results saved to ${outputFilePath}`);
}

program
  .name('bridge-demo')
  .description('A POC Bridge Implementation for OP_CAT-enabled Bitcoin.')
  .version(version);

program
  .command('aggregate-deposits')
  .description('Create deposit leaf txns and aggregate them into a single root txn')
  .argument('<depositsFile>', 'Path to JSON file with deposits data')
  .option('-o, --output <outputFile>', 'Path to the output JSON file to store aggregation results')
  .action(aggregateDeposits);
  
program
  .command('aggregate-withdrawals')
  .description('Create withdrawal request leaf txns and aggregate them into a single root txn')
  .argument('<withdrawalsFile>', 'Path to JSON file with withdrwal request data')
  .option('-o, --output <outputFile>', 'Path to the output JSON file to store aggregation results')
  .action(aggregateWithdrawals);

program.parse(process.argv);