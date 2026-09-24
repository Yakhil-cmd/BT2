No vulnerability found for this question.

The CVE-2017-17524 bug class—argument injection via an unsanitized string (the `BROWSER` environment variable) passed into a program-launch call—requires a code path where attacker-controlled input from a real user entry point (signed extrinsic, contract call, XCM message) is used to construct arguments for spawning an external process. Searching the Polkadot SDK for `Command::new`/`std::process::Command` usage shows it is confined to CLI tooling, build scripts, test harnesses, benchmarking utilities, and the PVF worker-spawning logic in `polkadot/node/core/pvf/src/worker_interface.rs` and `polkadot/node/core/pvf/src/security.rs`, none of which take arguments derived from consensus-reachable extrinsic/XCM/contract-call payloads [1](#0-0) [2](#0-1) . There is no `BROWSER` environment-variable handling or equivalent "launch program from untrusted string" pattern reachable via runtime/FRAME dispatch, contracts/revive execution, or pallet-xcm processing in this repository. Since no attacker-controlled entry point maps onto the missing-validation-before-process-launch invariant from the report, no demonstrable analog exists in production runtime code.

### Citations

**File:** polkadot/node/core/pvf/src/worker_interface.rs (L1-1)
```rust
// Copyright (C) Parity Technologies (UK) Ltd.
```

**File:** polkadot/node/core/pvf/src/security.rs (L1-1)
```rust
// Copyright (C) Parity Technologies (UK) Ltd.
```
