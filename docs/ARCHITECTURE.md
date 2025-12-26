# W3Registrar Architecture

## Current Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                        W3Registrar                          │
├─────────────────────────────────────────────────────────────┤
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐         │
│  │   Matrix    │  │    Email    │  │   GitHub    │         │
│  │   Adapter   │  │   Adapter   │  │   Adapter   │         │
│  └──────┬──────┘  └──────┬──────┘  └──────┬──────┘         │
│         │                │                │                 │
│  ┌──────┴────────────────┴────────────────┴──────┐         │
│  │              Verification Core                 │         │
│  │  - Token generation                           │         │
│  │  - Challenge verification                     │         │
│  │  - PGP signature verification                 │         │
│  └──────────────────────┬────────────────────────┘         │
│                         │                                   │
│  ┌──────────────────────┴────────────────────────┐         │
│  │              State Management                  │         │
│  │  ┌─────────┐  ┌───────────┐  ┌─────────────┐  │         │
│  │  │  Redis  │  │  Postgres │  │   On-chain  │  │         │
│  │  │ (cache) │  │ (persist) │  │   (final)   │  │         │
│  │  └─────────┘  └───────────┘  └─────────────┘  │         │
│  └───────────────────────────────────────────────┘         │
└─────────────────────────────────────────────────────────────┘
```

## Feature Flags

The application supports optional features to reduce build times:

- `matrix` - Matrix SDK for Matrix/Discord/Twitter verification (default: on)
- `mail` - IMAP support for email verification (default: on)

Build minimal binary:
```bash
cargo build --no-default-features
```

## JAM/PolkaVM Target Architecture

### Goal

Run verification logic as a JAM service (PVM guest function) for trustless
on-chain verification. The current off-chain worker model would transition
to an on-chain executor with off-chain data providers.

### Constraints

1. **No networking in PVM**: JAM services run in PolkaVM which lacks network access
2. **Deterministic execution**: All inputs must be provided via host functions
3. **Limited syscalls**: Only JAM-provided host functions available

### Proposed Design

```
┌─────────────────────────────────────────────────────────────────┐
│                         JAM Network                              │
├─────────────────────────────────────────────────────────────────┤
│  ┌───────────────────────────────────────────────────────────┐  │
│  │                    JAM Service (PVM)                       │  │
│  │  ┌─────────────────────────────────────────────────────┐  │  │
│  │  │            Verification Core (pure Rust)             │  │  │
│  │  │  - Token generation (deterministic RNG from block)   │  │  │
│  │  │  - Challenge verification (pure computation)         │  │  │
│  │  │  - PGP signature verification (sequoia-openpgp)      │  │  │
│  │  └──────────────────────┬──────────────────────────────┘  │  │
│  │                         │                                  │  │
│  │  ┌──────────────────────┴──────────────────────────────┐  │  │
│  │  │             Host Functions (JAM API)                 │  │  │
│  │  │  - read(service_id, key) -> data                    │  │  │
│  │  │  - write(key, data)                                  │  │  │
│  │  │  - lookup(service_id)                                │  │  │
│  │  └─────────────────────────────────────────────────────┘  │  │
│  └───────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
                              ▲
                              │ Extrinsics / Refinement
                              │
┌─────────────────────────────┴───────────────────────────────────┐
│                    Off-chain Data Providers                      │
├─────────────────────────────────────────────────────────────────┤
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐             │
│  │   Matrix    │  │    Email    │  │   GitHub    │             │
│  │   Watcher   │  │   Watcher   │  │   Watcher   │             │
│  └──────┬──────┘  └──────┬──────┘  └──────┬──────┘             │
│         │                │                │                     │
│  ┌──────┴────────────────┴────────────────┴──────┐             │
│  │              Evidence Collector               │             │
│  │  - Collects verification proofs              │             │
│  │  - Signs with validator key                   │             │
│  │  - Submits to JAM refinement                  │             │
│  └───────────────────────────────────────────────┘             │
└─────────────────────────────────────────────────────────────────┘
```

### Implementation Strategy

1. **Phase 1: Trait Abstraction** (current)
   - `VerificationStore`, `TimelineStore`, `ChainRegistrar` traits
   - Mock implementations for testing
   - Clean separation of concerns

2. **Phase 2: Pure Core**
   - Extract verification logic to `no_std` compatible crate
   - Remove all I/O from core verification
   - Use trait objects for state access

3. **Phase 3: PVM Guest**
   - Build verification core for PolkaVM target
   - Implement JAM host function bindings
   - Deterministic token generation from block entropy

4. **Phase 4: Off-chain Workers**
   - Lightweight watchers for each adapter
   - Evidence collection and signing
   - Submit proofs via extrinsics

### PolkaKernel Integration

The project at `~/rotko/polkaports` provides polkakernel which supports
std Rust on PolkaVM. This may simplify porting by:

- Allowing std library usage where possible
- Providing network abstractions via kernel syscalls
- Enabling incremental migration

### Challenges

1. **Networking**: Need to bridge external API calls through off-chain workers
2. **PGP**: sequoia-openpgp may need modifications for PVM
3. **State**: Redis/Postgres must be replaced with on-chain storage
4. **Randomness**: Token generation needs deterministic entropy source

### Benefits

1. **Trustless**: Verification runs on-chain, no trusted operators
2. **Decentralized**: Anyone can run off-chain watchers
3. **Auditable**: All verification logic is transparent
4. **Composable**: Other services can verify identities directly
