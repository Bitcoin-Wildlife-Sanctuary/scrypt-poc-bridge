# sCrypt POC Bridge Covenant

Implementation of the POC bridge covenant for StarkNet.

## Configure Private Key

First, we need to create a .env file with our private key, which should contain some signet funds:

```
PRIVATE_KEY="cTE..."
```

You may obtain signet funds via these faucets:
- https://signetfaucet.com/
- https://alt.signetfaucet.com
- https://x.com/babylon_chain/status/1790787732643643575


## Install Dependencies

```sh
npm i
```

## Build

```sh
npm run build
```

## Testing Locally

The following command will run a full end-to-end test locally. This includes assembly and local execution of covenant transactions.

```sh
npm t
```

## Testing on Signet

To run the tests on the signet network, we need to run a local bitcoin inquisition node.

### Step 1: Install Bitcoin Core Inquisition

Download the Bitcoin Core Inquisition from [GitHub](https://github.com/bitcoin-inquisition/bitcoin/releases).

### Step 2: Connect to a CAT-ready Relay Node

The Bitcoin client will automatically find nearby relay nodes for broadcasting transactions. However, these nodes may not support the new OP_CAT version and could refuse to broadcast it due to default policies against OP_SUCCESSXX. Thus, we need to configure our node to relay transactions to an inquisition node.

Add the following to the node configuration:
```
signet=1
daemon=1

[signet]
addnode=inquisition.taprootwizards.com
```

### Step 3: Broadcast transactions

Once we have our node up and running, we can start broadcasting our transactions. The tests by default output the serialized transactions which run the smart contract.

```sh
npm run test:testnet
```

```
Deposit funding tx:
...
Deposit leaf tx 0:
...
Deposit leaf tx 1:
...
```

We can now broadcast the serialized transactions one by one using `bitcoin-cli`, which is bundled with your node software:

```sh
./bin/bitcoin-cli --conf=<path to node configuration> sendrawtransaction 020000000001022...
```

If everything succeeds, the command should output a TXID.

Note, that the TX may not be immediately visible on block explorers such as [Mempool](https://mempool.space/signet), since they only accept the transaction once it's mined into a block by an inquisition node.
