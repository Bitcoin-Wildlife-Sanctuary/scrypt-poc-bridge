// @ts-ignore
import btc = require('bitcore-lib-inquisition');
import { Tap } from '@cmdcode/tapscript'  // Requires node >= 19

import * as dotenv from 'dotenv';
dotenv.config();

import { expect, use } from 'chai'
import { DepositAggregator } from '../src/contracts/depositAggregator'
import chaiAsPromised from 'chai-as-promised'
import { PubKey, toByteString } from 'scrypt-ts';
use(chaiAsPromised)


describe('Test SmartContract `Counter`', () => {

    before(async () => {
        await DepositAggregator.loadArtifact()
    })

    it('should pass', async () => {
        const seckeyOperator = new btc.PrivateKey(process.env.PRIVATE_KEY, btc.Networks.testnet)
        const pubkeyOperator = seckeyOperator.toPublicKey()

        const instance = new DepositAggregator(
            PubKey(toByteString(pubkeyOperator.toString())),
            toByteString('00000000000000000000000000000000000000000000000000000000000000000000000000000000')
        )
        
        console.log('Script len:', instance.lockingScript.toBuffer().length)
        console.log('Script ASM:', instance.lockingScript.toASM())
    })

})