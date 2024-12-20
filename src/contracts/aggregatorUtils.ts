import { ByteString, hash256, len, method, OpCode, Sha256, sha256, SmartContractLib, toByteString } from "scrypt-ts";


export type AggregatorTransaction = {
    ver: ByteString
    inputContract0: ByteString
    inputContract1: ByteString
    inputFee: ByteString
    outputContractAmt: ByteString
    outputContractSPK: ByteString
    hashData: Sha256 // Hash of state data, stored in OP_RETURN output.
    locktime: ByteString
}

export class AggregatorUtils extends SmartContractLib {

    @method()
    static getTxId(tx: AggregatorTransaction, isLeaf: boolean): Sha256 {
        const inputsPrefix = isLeaf ?
            toByteString('02') + tx.inputContract0 :
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

}