// @ts-ignore
import btc = require('bitcore-lib-inquisition');
import axios from 'axios';
import * as ecurve from 'ecurve';
import { sha256 } from 'js-sha256';
// @ts-ignore
import BigInteger = require('bigi')
import { DummyProvider, DefaultProvider, TestWallet, bsv } from 'scrypt-ts'
import { myPrivateKey } from './privateKey'

import * as dotenv from 'dotenv'

// Load the .env file
dotenv.config()

const wallets: Record<string, TestWallet> = {
    testnet: new TestWallet(
        myPrivateKey,
        new DefaultProvider({
            network: bsv.Networks.testnet,
        })
    ),
    local: new TestWallet(myPrivateKey, new DummyProvider()),
    mainnet: new TestWallet(
        myPrivateKey,
        new DefaultProvider({
            network: bsv.Networks.mainnet,
        })
    ),
}

export const DISABLE_KEYSPEND_PUBKEY = '0250929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0'

export function getDefaultSigner(
    privateKey?: bsv.PrivateKey | bsv.PrivateKey[]
): TestWallet {
    const network = process.env.NETWORK || 'local'

    const wallet = wallets[network]

    if (privateKey) {
        wallet.addPrivateKey(privateKey)
    }

    return wallet
}

export const sleep = async (seconds: number) => {
    return new Promise((resolve) => {
        setTimeout(() => {
            resolve({})
        }, seconds * 1000)
    })
}

export function randomPrivateKey() {
    const privateKey = bsv.PrivateKey.fromRandom(bsv.Networks.testnet)
    const publicKey = bsv.PublicKey.fromPrivateKey(privateKey)
    const publicKeyHash = bsv.crypto.Hash.sha256ripemd160(publicKey.toBuffer())
    const address = publicKey.toAddress()
    return [privateKey, publicKey, publicKeyHash, address] as const
}

export async function fetchP2WPKHUtxos(address: btc.Address): Promise<any[]> {
    const network = process.env.NETWORK || 'local'

    if (network === 'local') {
        return [
            {
                address: address.toString(),
                txId: '00'.repeat(32),
                outputIndex: 0,
                script: new btc.Script(address),
                satoshis: 100000000000
            }
        ]
    }

    const url = `https://explorer.bc-2.jp/api/address/${address.toString()}/utxo`;

    let res: any[] = []
    try {
        // Make a GET request to the URL using axios
        const response = await axios.get(url, {
            timeout: 10000
        });

        if (response.data) {
            for (let i = 0; i < response.data.length; i++) {
                const e = response.data[i]
                const utxo = {
                    address: address.toString(),
                    txId: e.txid,
                    outputIndex: e.vout,
                    script: new btc.Script(address),
                    satoshis: e.value
                };
                res.push(utxo)
            }
        }
    } catch (error) { // Handle any errors that occurred during the request
        console.error('Failed to fetch data:', error);
    }
    return res
}

export const curveSECP256K1 = ecurve.getCurveByName('secp256k1');

export function hashSHA256(buff: Buffer | string) {
    return Buffer.from(sha256.create().update(buff).array());
}

export type SigHashSchnorr = {
    preimage: Buffer
    hash: Buffer
}

export function getSigHashSchnorr(
    transaction: btc.Transaction,
    tapleafHash: Buffer,
    inputIndex = 0,
    sigHashType = 0x00
): SigHashSchnorr {
    //const sighash = btc.Transaction.Sighash.sighash(transaction, sigHashType, inputIndex, subscript);
    const execdata = {
        annexPresent: false,
        annexInit: true,
        tapleafHash: tapleafHash,
        tapleafHashInit: true,
        ////validationWeightLeft: 110,
        ////validationWeightLeftInit: true,
        codeseparatorPos: new btc.crypto.BN(4294967295),
        codeseparatorPosInit: true,
    }

    return {
        preimage: btc.Transaction.SighashSchnorr.sighashPreimage(transaction, sigHashType, inputIndex, 3, execdata),
        hash: btc.Transaction.SighashSchnorr.sighash(transaction, sigHashType, inputIndex, 3, execdata)
    }
}

export function getE(
    sighash: Buffer
) {
    const Gx = curveSECP256K1.G.affineX.toBuffer(32);

    const tagHash = hashSHA256('BIP0340/challenge')
    const tagHashMsg = Buffer.concat([Gx, Gx, sighash])
    const taggedHash = hashSHA256(Buffer.concat([tagHash, tagHash, tagHashMsg]))

    return BigInteger.fromBuffer(taggedHash).mod(curveSECP256K1.n);
}

export type SighashPreimageParts = {
    tapSighash1: Buffer
    tapSighash2: Buffer
    epoch: Buffer
    sighashType: Buffer
    txVersion: Buffer
    nLockTime: Buffer
    hashPrevouts: Buffer
    hashSpentAmounts: Buffer
    hashScripts: Buffer
    hashSequences: Buffer
    hashOutputs: Buffer
    spendType: Buffer
    inputNumber: Buffer
    tapleafHash: Buffer
    keyVersion: Buffer
    codeseparatorPosition: Buffer
}

export function splitSighashPreimage(preimage: Buffer): SighashPreimageParts {
    return {
        tapSighash1: preimage.slice(0, 32),
        tapSighash2: preimage.slice(32, 64),
        epoch: preimage.slice(64, 65),
        sighashType: preimage.slice(65, 66),
        txVersion: preimage.slice(66, 70),
        nLockTime: preimage.slice(70, 74),
        hashPrevouts: preimage.slice(74, 106),
        hashSpentAmounts: preimage.slice(106, 138),
        hashScripts: preimage.slice(138, 170),
        hashSequences: preimage.slice(170, 202),
        hashOutputs: preimage.slice(202, 234),
        spendType: preimage.slice(234, 235),
        inputNumber: preimage.slice(235, 239),
        tapleafHash: preimage.slice(239, 271),
        keyVersion: preimage.slice(271, 272),
        codeseparatorPosition: preimage.slice(272)
    };
}

export type SchnorrTrickData = {
    sighash: SigHashSchnorr
    e: BigInteger
    eBuff: Buffer
    eLastByte: number
    _e: Buffer // e' - e without last byte 
    preimageParts: SighashPreimageParts
}

export async function schnorrTrick(
    tx: btc.Transaction,
    tapleafHex: string,
    inputIndex: number = 0
): Promise<SchnorrTrickData> {
    // Mutate tx if it ends with 0x7f (highest single byte stack value) or 0xff (lowest signle byte stack value).
    let e, eBuff, sighash, eLastByte;
    while (true) {
        sighash = getSigHashSchnorr(tx, Buffer.from(tapleafHex, 'hex'), inputIndex)
        e = await getE(sighash.hash)
        eBuff = e.toBuffer(32)
        eLastByte = eBuff[eBuff.length - 1]
        if (eLastByte != 0x7f && eLastByte != 0xff) {
            break;
        }
        tx.nLockTime += 1
    }

    let _e = eBuff.slice(0, eBuff.length - 1) // e' - e without last byte
    let preimageParts = splitSighashPreimage(sighash.preimage)

    return {
        sighash,
        e,
        eBuff,
        eLastByte,
        _e,
        preimageParts
    }
}

export function hexLEtoDecimal(hexLE: string): number {
  const bytes = hexLE.match(/.{2}/g);

  if (!bytes) {
    throw new Error("Invalid hexadecimal format.");
  }

  const hexBE = bytes.reverse().join("");
  return parseInt(hexBE, 16);
}


