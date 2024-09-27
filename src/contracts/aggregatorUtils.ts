import { assert, ByteString, hash256, int2ByteString, len, method, OpCode, Sha256, sha256, SmartContractLib, toByteString } from "scrypt-ts";


export type AggregatorTransaction = {
    ver: ByteString
    inputContract0: ByteString
    inputContract1: ByteString
    inputFee: ByteString
    outputContractAmt: ByteString
    outputContractSPK: ByteString
    hashData: ByteString // Hash of state data, stored in OP_RETURN output.
    locktime: ByteString
}

export class AggregatorUtils extends SmartContractLib {

    @method()
    static getTxId(tx: AggregatorTransaction, isPrevTxLeaf: boolean): Sha256 {
        const inputsPrefix = isPrevTxLeaf ?
            toByteString('01') :
            (toByteString('03') + tx.inputContract0 + tx.inputContract1)
        return hash256(
            tx.ver +
            inputsPrefix +
            tx.inputFee +
            toByteString('02') +
            tx.outputContractAmt + tx.outputContractSPK +
            toByteString('000000000000000022') +
            OpCode.OP_RETURN +
            toByteString('20') +
            tx.hashData +
            tx.locktime
        )
    }

    @method()
    static getHashPrevouts(
        txId0: Sha256,
        txId1: Sha256,
        feePrevout: ByteString
    ): Sha256 {
        return sha256(
            txId0 +
            toByteString('00000000') +
            txId1 +
            toByteString('00000000') +
            feePrevout
        )
    }

    @method()
    static padAmt(amt: bigint): ByteString {
        let res = int2ByteString(amt)
        if (amt < 0x0100n) {
            res += toByteString('00000000000000')
        } else if (amt < 0x010000n) {
            res += toByteString('000000000000')
        } else if (amt < 0x01000000n) {
            res += toByteString('0000000000')
        } else {
            assert(false, 'bad amt')
        }
        return res
    }

    @method()
    static getStateOutput(hash: Sha256): ByteString {
        return toByteString('0000000000000000') + // Output satoshis (0 sats)
            toByteString('22') +               // Script lenght (34 bytes)
            OpCode.OP_RETURN +
            toByteString('20') +               // Hash length (32 bytes)
            hash
    }

    @method()
    static getContractOutput(amt: bigint, spk: ByteString): ByteString {
        assert(len(spk) == 35n)
        return AggregatorUtils.padAmt(amt) + spk
    }

}