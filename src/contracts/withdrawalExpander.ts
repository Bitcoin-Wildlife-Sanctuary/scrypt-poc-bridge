import { assert, ByteString, hash256, method, prop, PubKey, sha256, Sha256, Sig, SmartContract, toByteString } from "scrypt-ts";
import { SHPreimage, SigHashUtils } from "./sigHashUtils";
import { Bridge, BridgeTransaction } from "./bridge";
import { WithdrawalData } from "./withdrawalAggregator";
import { AggregatorUtils } from "./aggregatorUtils";
import { GeneralUtils } from "./generalUtils";


export type ExpanderTransaction = {
    ver: ByteString
    inputContract: ByteString
    inputFee: ByteString
    expanderSPK: ByteString
    output0Amt: bigint
    output1Amt: bigint
    hashData0: Sha256
    hashData1: Sha256
    locktime: ByteString
}

export class WithdrawalExpander extends SmartContract {

    @prop()
    operator: PubKey

    constructor(
        operator: PubKey
    ) {
        super(...arguments)
        this.operator = operator
    }


    @method()
    public expand(
        shPreimage: SHPreimage,
        sigOperator: Sig,

        isExpandingPrevTxFirstOutput: boolean,
        isPrevTxBridge: boolean,
        prevTxBridge: BridgeTransaction,
        prevTxExpander: ExpanderTransaction,

        isExpandingLeaves: boolean,
        withdrawalData0: WithdrawalData,
        withdrawalData1: WithdrawalData,

        fundingPrevout: ByteString
    ) {
        // Check sighash preimage.
        const s = SigHashUtils.checkSHPreimage(shPreimage)
        assert(this.checkSig(s, SigHashUtils.Gx))

        // Check operator sig.
        assert(this.checkSig(sigOperator, this.operator))

        // Construct prev tx ID.
        let prevTxId = Sha256(toByteString(''))
        if (isPrevTxBridge) {
            prevTxId = WithdrawalExpander.getBridgeTxId(prevTxBridge)
        } else {
            prevTxId = WithdrawalExpander.getTxId(prevTxExpander)
        }
        
        // Check passed prev tx is actually unlocked by the currently executing tx.
        const hashPrevouts = WithdrawalExpander.getHashPrevouts(
            prevTxId,
            fundingPrevout
        )
        assert(hashPrevouts == shPreimage.hashPrevouts)
        
        // Check we're unlocking contract UTXO via the first input.
        assert(shPreimage.inputNumber == toByteString('00000000'))
        
        

    }

    @method()
    static getTxId(tx: ExpanderTransaction): Sha256 {
        const stateHash = WithdrawalExpander.getStateHash(tx.hashData0, tx.hashData1)
        return hash256(
            tx.ver +
            toByteString('02') +
            tx.inputContract +
            tx.inputFee + 
            toByteString('03') +
            GeneralUtils.getContractOutput(tx.output0Amt, tx.expanderSPK) +
            GeneralUtils.getContractOutput(tx.output1Amt, tx.expanderSPK) +
            GeneralUtils.getStateOutput(stateHash) +
            tx.locktime
        )
    }
    
    @method()
    static getBridgeTxId(tx: BridgeTransaction): Sha256 {
        const stateHash = Bridge.getStateHash(
            tx.accountsRoot, tx.depositAggregatorSPK, tx.withdrawalAggregatorSPK, tx.expanderRoot
        )
        return hash256(
            tx.ver +
            tx.inputs +
            toByteString('03') +
            GeneralUtils.getContractOutput(tx.contractAmt, tx.contractSPK) +
            GeneralUtils.getStateOutput(stateHash) +
            GeneralUtils.getContractOutput(tx.expanderAmt, tx.expanderSPK) +
            tx.locktime
        )
    }
    
    @method()
    static getHashPrevouts(
        txId: Sha256,
        feePrevout: ByteString
    ): Sha256 {
        return sha256(
            txId +
            toByteString('00000000') +
            feePrevout
        )
    }
    
    @method()
    static getStateHash(
        hash0: Sha256,
        hash1: Sha256
    ): Sha256 {
        return hash256(hash0 + hash1) 
    }

}