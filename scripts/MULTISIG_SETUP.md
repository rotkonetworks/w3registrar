# Registrar Multisig Setup

This guide explains how to set up a registrar controlled by a 3-of-5 multisig with a pure proxy.

## Architecture

```
3-of-5 Multisig (cold storage, owns everything)
    └── Pure Proxy (the registrar account on-chain)
            └── IdentityJudgement Proxy (hot wallet for w3registrar backend)
```

**Why this structure?**
- **Multisig**: Requires 3 of 5 signatories to make any changes (security)
- **Pure Proxy**: The actual registrar address submitted to governance; owned by multisig
- **IdentityJudgement Proxy**: Hot wallet that can only call `identity.provideJudgement`

## Quick Start

### 1. Calculate Multisig Address

```bash
cd scripts && npm install

npx ts-node setup_registrar_multisig.ts \
  --network kusama \
  --signatories addr1,addr2,addr3,addr4,addr5 \
  --threshold 3 \
  --hot-wallet <hot_wallet_address>
```

This outputs the deterministic multisig address and step-by-step instructions.

### 2. Fund the Multisig

Send some KSM to the multisig address for transaction fees.

### 3. Create Pure Proxy (requires 3 signatures)

All signatories coordinate via Polkadot-JS Apps:

1. Go to https://polkadot.js.org/apps/?rpc=wss://kusama-people-rpc.polkadot.io#/extrinsics

2. **First signatory** submits:
   ```
   multisig.asMulti(
     threshold: 3,
     otherSignatories: [addr2, addr3, addr4, addr5],  // exclude self
     maybeTimepoint: null,
     call: proxy.createPure(proxyType: Any, delay: 0, index: 0),
     maxWeight: { refTime: 1000000000, proofSize: 100000 }
   )
   ```

3. **Note the timepoint** from the MultisigApproval event (block number + tx index)

4. **Second signatory** submits:
   ```
   multisig.asMulti(
     threshold: 3,
     otherSignatories: [addr1, addr3, addr4, addr5],  // exclude self
     maybeTimepoint: { height: <block>, index: <txIndex> },
     call: proxy.createPure(proxyType: Any, delay: 0, index: 0),
     maxWeight: { refTime: 1000000000, proofSize: 100000 }
   )
   ```

5. **Third signatory** submits same (this executes the call)

6. Check events for `proxy.PureCreated` - note the pure proxy address!

### 4. Add Hot Wallet as Proxy (requires 3 signatures)

The hot wallet needs `IdentityJudgement` proxy rights on the pure proxy:

1. **First signatory** submits:
   ```
   multisig.asMulti(
     threshold: 3,
     otherSignatories: [...],
     maybeTimepoint: null,
     call: proxy.proxy(
       real: <pure_proxy_address>,
       forceProxyType: null,
       call: proxy.addProxy(
         delegate: <hot_wallet_address>,
         proxyType: IdentityJudgement,
         delay: 0
       )
     ),
     maxWeight: { refTime: 1000000000, proofSize: 100000 }
   )
   ```

2. Second and third signatories approve as before

### 5. Submit Governance Proposal

Once the pure proxy is set up, submit a referendum to add it as registrar:

```bash
npx ts-node generate_registrar_proposal.ts <pure_proxy_address>
```

This outputs the XCM call for adding the registrar on the People Chain.

### 6. Configure w3registrar Backend

Update your config to use the hot wallet:

```toml
[registrar.kusama]
endpoint = "wss://kusama-people-rpc.polkadot.io"
active = true
registrar_index = <your_index>  # assigned after governance approval
registrar_account = "<pure_proxy_address>"
keystore_path = "./.keyfile.kusama"  # hot wallet keyfile
fields = ["email", "matrix", "twitter", "discord", "display_name"]
```

The hot wallet signs `identity.provideJudgement` calls, which are proxied through the pure proxy.

## Security Notes

- **Never expose multisig signatory keys** - they control everything
- **Hot wallet has limited permissions** - can only provide judgements
- **Changing the hot wallet** requires 3-of-5 multisig approval
- **Removing the registrar** would require governance (same process as adding)

## Useful Links

- [Polkadot-JS Apps (Kusama People)](https://polkadot.js.org/apps/?rpc=wss://kusama-people-rpc.polkadot.io)
- [Multisig Documentation](https://wiki.polkadot.network/docs/learn-account-multisig)
- [Proxy Documentation](https://wiki.polkadot.network/docs/learn-proxies)
