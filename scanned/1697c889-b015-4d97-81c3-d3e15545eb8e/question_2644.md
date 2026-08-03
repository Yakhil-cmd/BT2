# Q2644: refund-beneficiary mismatch via polkadotxcm execute send on People Polkadot runtime

## Question
Can an unprivileged attacker enter through `PolkadotXcm::{execute, send}` on People Polkadot runtime and control batched updates that mutate both identity deposits and transferable balances before finalization so that `construct_runtime! / RuntimeCall::{Identity, Assets, PolkadotXcm, Proxy, Utility}` makes proxy, multisig, or XCM execution observe a different account state than the identity logic uses for charges or refunds, breaking the invariant that identity slashing and treasury routing must not leak funds to attacker-chosen beneficiaries, and leading to critical - direct loss of funds through misrouted refund, slash, or asset movement?

## Target
- File/function: `system-parachains/people/people-polkadot/src/lib.rs` :: `construct_runtime! / RuntimeCall::{Identity, Assets, PolkadotXcm, Proxy, Utility}`
- Entrypoint: `PolkadotXcm::{execute, send}`
- Attacker controls: batched updates that mutate both identity deposits and transferable balances before finalization
- Exploit idea: makes proxy, multisig, or XCM execution observe a different account state than the identity logic uses for charges or refunds
- Invariant to test: identity slashing and treasury routing must not leak funds to attacker-chosen beneficiaries
- Expected Immunefi impact: Critical - direct loss of funds through misrouted refund, slash, or asset movement
- Fast validation: xcm-emulator or proxy test if the path depends on aliased locations or nested execution
