# Adding a Registrar on Kusama People Chain

This guide explains how to submit an OpenGov proposal to add a registrar on the
Kusama People Chain via XCM from the relay chain.

## Overview

Since identity has migrated to the People Chain (a system parachain), adding a
registrar requires:

1. Creating a preimage with an XCM message that calls `Identity.add_registrar`
   on the People Chain
2. Submitting a referendum on the Root track
3. Waiting for voting and enactment

## Prerequisites

- Kusama account with funds for:
  - Preimage deposit (~0.01 KSM)
  - Referendum submission deposit (varies by track)
- The registrar account address (SS58 format for Kusama)

## Identity Fields (Bitflags)

When setting up the registrar after approval, use these field values:

| Field           | Decimal |
|-----------------|---------|
| Display         | 1       |
| Legal           | 2       |
| Web             | 4       |
| Matrix          | 8       |
| Email           | 16      |
| PGP Fingerprint | 32      |
| Image           | 64      |
| Twitter         | 128     |
| GitHub          | 256     |
| Discord         | 512     |

**Standard W3Reg fields (665)**: Display + Matrix + Email + Twitter + Discord

## Step 1: Construct the XCM Call

The XCM message needs to:
1. Target the People Chain (ParaId 1004 on Kusama)
2. Use `Transact` with Root origin
3. Execute `Identity.add_registrar(account)`

### Using Polkadot-JS Apps

1. Go to https://polkadot.js.org/apps/?rpc=wss://kusama-rpc.polkadot.io
2. Navigate to Developer > Extrinsics
3. Select `xcmPallet.send`

**Destination:**
```
V4 {
  parents: 0,
  interior: X1(Parachain(1004))
}
```

**Message:**
```
V4([
  UnpaidExecution {
    weight_limit: Unlimited,
    check_origin: None
  },
  Transact {
    origin_kind: Superuser,
    require_weight_at_most: { ref_time: 1_000_000_000, proof_size: 100_000 },
    call: <encoded Identity.add_registrar call>
  }
])
```

### Encoding the Inner Call

The inner call to be transacted is `Identity.add_registrar(account)`:

1. Go to https://polkadot.js.org/apps/?rpc=wss://people-kusama.dotters.network
2. Navigate to Developer > Extrinsics
3. Select `identity.addRegistrar`
4. Enter the registrar account address
5. Copy the encoded call data (hex)

## Step 2: Create the Preimage

1. Go to Governance > Preimages on Kusama relay chain
2. Click "Add preimage"
3. Select `xcmPallet.send` with the parameters above
4. Submit and note the preimage hash

## Step 3: Submit Referendum

1. Go to Governance > Referenda
2. Click "Submit proposal"
3. Select Origin: Root (required for add_registrar)
4. Enter the preimage hash
5. Submit with required deposit

## Step 4: Post-Approval Setup

After the referendum passes and enacts:

1. **Set registrar fee** (on People Chain):
   ```
   identity.setFee(registrar_index, fee_amount)
   ```

2. **Set verification fields** (on People Chain):
   ```
   identity.setFields(registrar_index, 665)
   ```

3. **Add proxy for hot wallet** (optional but recommended):
   ```
   proxy.addProxy(hot_wallet_address, IdentityJudgement, 0)
   ```

## Testing on Local Network

See `scripts/test_add_registrar.sh` for testing this flow on a local testnet
using zombienet.

## Governance Track Details

### Kusama Root Track Parameters

- Decision period: 14 days
- Min approval: 93.5% early, curves down
- Min support: 48.2% early, curves to ~0%
- Confirm period: 1 day
- Enactment: 1 day minimum

### Tips for Passing

1. Write a detailed forum post before submitting
2. Explain your registrar service and verification methods
3. Share your track record if you have one
4. Engage with the community during voting
5. Request endorsements to move up the queue

## References

- [Polkadot Identity Guides](https://wiki.polkadot.com/docs/learn-guides-identity)
- [OpenGov Origins and Tracks](https://docs.polkadot.com/polkadot-protocol/onchain-governance/origins-tracks/)
- [XCM Documentation](https://wiki.polkadot.com/learn/learn-xcm/)
- [Chevdor's Registrar Guide](https://www.chevdor.com/post/2020/01/17/registrar1/)
