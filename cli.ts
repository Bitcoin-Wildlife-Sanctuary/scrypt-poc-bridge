#!/usr/bin/env ts-node

import * as fs from 'fs';
import path from 'path';
import { Command } from 'commander';
import { version } from './package.json';
import { Bridge } from './src/contracts/bridge'
import {
  myAddress as operatorAddress,
  myPrivateKey as operatorPrivateKey,
  myPublicKey as operatorPublicKey
} from './src/utils/privateKey';
import { DepositAggregator } from './src/contracts/depositAggregator';
// @ts-ignore
import btc = require('bitcore-lib-inquisition');
import { createContractInstances, fetchP2WPKHUtxos } from './src/utils/txHelper';
import { WithdrawalAggregator } from './src/contracts/withdrawalAggregator';
import { WithdrawalExpander } from './src/contracts/withdrawalExpander';
import ARTIFACT_DEPOSIT_AGGREGATOR from './artifacts/depositAggregator.json'
import ARTIFACT_WITHDRAWAL_AGGREGATOR from './artifacts/withdrawalAggregator.json'
import ARTIFACT_BRIDGE from './artifacts/bridge.json'
import ARTIFACT_WITHDRAWAL_EXPANDER from './artifacts/withdrawalExpander.json'
import { performDepositAggregation } from './src/utils/depositAggregation';
import { performWithdrawalAggregation } from './src/utils/withrawalAggreagation';
import { deployBridge } from './src/utils/bridge';

const program = new Command();

async function loadContractsInfo(
  operatorPublicKey: btc.PublicKey
) {
  await DepositAggregator.loadArtifact(ARTIFACT_DEPOSIT_AGGREGATOR)
  await WithdrawalAggregator.loadArtifact(ARTIFACT_WITHDRAWAL_AGGREGATOR)
  await Bridge.loadArtifact(ARTIFACT_BRIDGE)
  await WithdrawalExpander.loadArtifact(ARTIFACT_WITHDRAWAL_EXPANDER)

  return createContractInstances(operatorPublicKey)
}

async function aggregateDeposits(inputFile: string, options: { output: string }) {
  const { output } = options;

  // Read and parse the input JSON file
  const inputFilePath = path.resolve(inputFile);
  const deposits = JSON.parse(fs.readFileSync(inputFilePath, 'utf-8'));

  const contractsInfo = await loadContractsInfo(operatorPublicKey)

  // Create transactions used to fund our test txns.
  let operatorUTXOs = await fetchP2WPKHUtxos(operatorAddress)
  if (operatorUTXOs.length === 0) {
    throw new Error(`No UTXO's for address: ${operatorPrivateKey.toString()}`)
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
    operatorPrivateKey
  )

  // Evaluate txns locally
  let interpreter = new btc.Script.Interpreter()
  let flags = btc.Script.Interpreter.SCRIPT_VERIFY_WITNESS | btc.Script.Interpreter.SCRIPT_VERIFY_TAPROOT | btc.Script.Interpreter.SCRIPT_VERIFY_DISCOURAGE_OP_SUCCESS

  let evalRes = interpreter.verify(new btc.Script(''), aggregationRes.leafTxns[0].outputs[0].script, aggregationRes.aggregateTxns[0], 0, flags, aggregationRes.aggregateTxns[0].inputs[0].witnesses, aggregationRes.leafTxns[0].outputs[0].satoshis)
  evalRes &= interpreter.verify(new btc.Script(''), aggregationRes.leafTxns[1].outputs[0].script, aggregationRes.aggregateTxns[0], 1, flags, aggregationRes.aggregateTxns[0].inputs[1].witnesses, aggregationRes.leafTxns[1].outputs[0].satoshis)
  evalRes &= interpreter.verify(new btc.Script(''), aggregationRes.leafTxns[2].outputs[0].script, aggregationRes.aggregateTxns[1], 0, flags, aggregationRes.aggregateTxns[1].inputs[0].witnesses, aggregationRes.leafTxns[2].outputs[0].satoshis)
  evalRes &= interpreter.verify(new btc.Script(''), aggregationRes.leafTxns[3].outputs[0].script, aggregationRes.aggregateTxns[1], 1, flags, aggregationRes.aggregateTxns[1].inputs[1].witnesses, aggregationRes.leafTxns[3].outputs[0].satoshis)
  evalRes &= interpreter.verify(new btc.Script(''), aggregationRes.aggregateTxns[0].outputs[0].script, aggregationRes.aggregateTxns[2], 0, flags, aggregationRes.aggregateTxns[2].inputs[0].witnesses, aggregationRes.aggregateTxns[0].outputs[0].satoshis)
  evalRes &= interpreter.verify(new btc.Script(''), aggregationRes.aggregateTxns[1].outputs[0].script, aggregationRes.aggregateTxns[2], 1, flags, aggregationRes.aggregateTxns[2].inputs[1].witnesses, aggregationRes.aggregateTxns[1].outputs[0].satoshis)

  if (!evalRes) {
    throw Error('Local script evaluation failed.')
  }

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

  const contractsInfo = await loadContractsInfo(operatorPublicKey)

  // Create transactions used to fund our test txns.
  let operatorUTXOs = await fetchP2WPKHUtxos(operatorAddress)
  if (operatorUTXOs.length === 0) {
    throw new Error(`No UTXO's for address: ${operatorPrivateKey.toString()}`)
  }

  const txFee = 3000

  const aggregationRes = await performWithdrawalAggregation(
    operatorUTXOs,
    withdrawals,
    txFee,
    contractsInfo.withdrawalAggregator.scriptP2TR,
    contractsInfo.withdrawalAggregator.cblock,
    contractsInfo.withdrawalAggregator.script,
    contractsInfo.withdrawalAggregator.tapleaf,
    operatorPrivateKey
  )

  // Evaluate txns locally
  let interpreter = new btc.Script.Interpreter()
  let flags = btc.Script.Interpreter.SCRIPT_VERIFY_WITNESS | btc.Script.Interpreter.SCRIPT_VERIFY_TAPROOT | btc.Script.Interpreter.SCRIPT_VERIFY_DISCOURAGE_OP_SUCCESS

  let evalRes = interpreter.verify(new btc.Script(''), aggregationRes.leafTxns[0].outputs[0].script, aggregationRes.aggregateTxns[0], 0, flags, aggregationRes.aggregateTxns[0].inputs[0].witnesses, aggregationRes.leafTxns[0].outputs[0].satoshis)
  evalRes &= interpreter.verify(new btc.Script(''), aggregationRes.leafTxns[1].outputs[0].script, aggregationRes.aggregateTxns[0], 1, flags, aggregationRes.aggregateTxns[0].inputs[1].witnesses, aggregationRes.leafTxns[1].outputs[0].satoshis)
  evalRes &= interpreter.verify(new btc.Script(''), aggregationRes.leafTxns[2].outputs[0].script, aggregationRes.aggregateTxns[1], 0, flags, aggregationRes.aggregateTxns[1].inputs[0].witnesses, aggregationRes.leafTxns[2].outputs[0].satoshis)
  evalRes &= interpreter.verify(new btc.Script(''), aggregationRes.leafTxns[3].outputs[0].script, aggregationRes.aggregateTxns[1], 1, flags, aggregationRes.aggregateTxns[1].inputs[1].witnesses, aggregationRes.leafTxns[3].outputs[0].satoshis)
  evalRes &= interpreter.verify(new btc.Script(''), aggregationRes.aggregateTxns[0].outputs[0].script, aggregationRes.aggregateTxns[2], 0, flags, aggregationRes.aggregateTxns[2].inputs[0].witnesses, aggregationRes.aggregateTxns[0].outputs[0].satoshis)
  evalRes &= interpreter.verify(new btc.Script(''), aggregationRes.aggregateTxns[1].outputs[0].script, aggregationRes.aggregateTxns[2], 1, flags, aggregationRes.aggregateTxns[2].inputs[1].witnesses, aggregationRes.aggregateTxns[1].outputs[0].satoshis)

  if (!evalRes) {
    throw Error('Local script evaluation failed.')
  }

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


async function bridgeDeploy(options: { output: string }) {
  const { output } = options;

  const contractsInfo = await loadContractsInfo(operatorPublicKey)

  // Create transactions used to fund our test txns.
  let operatorUTXOs = await fetchP2WPKHUtxos(operatorAddress)
  if (operatorUTXOs.length === 0) {
    throw new Error(`No UTXO's for address: ${operatorPrivateKey.toString()}`)
  }

  const txFee = 3000

  const { bridgeData, deployTx } = deployBridge(
    operatorUTXOs,
    txFee,
    contractsInfo.bridge.scriptP2TR,
    contractsInfo.depositAggregator.scriptP2TR,
    contractsInfo.withdrawalAggregator.scriptP2TR,
  )

  const res = {
    bridgeData,
    latestTx: deployTx
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

program
  .command('bridge-deploy')
  .description('Create bridge covenant deployment txn')
  .option('-o, --output <outputFile>', 'Path to the output JSON file to store new bridge data')
  .action(bridgeDeploy);

program
  .command('bridge-deposit')
  .description('Merge deposit aggregation result into bridge covenant')
  .argument('<bridgeDataFile>', 'Path to JSON file with latest bridge state')
  .argument('<depositAggregationResFile>', 'Path to JSON file with deposit aggregation results')
  .option('-o, --output <outputFile>', 'Path to the output JSON file to store new bridge data')
  .action(() => { });

program.parse(process.argv);