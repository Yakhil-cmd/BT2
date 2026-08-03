# Q2924: identity-deposit drift via proxy proxy multisig as on People Kusama runtime

## Question
Can an unprivileged attacker enter through `Proxy::proxy` / `Multisig::as_multi` / `Utility::batch_all` on People Kusama runtime and control batched updates that mutate both identity deposits and transferable balances before finalization so that `construct_runtime! / RuntimeCall::{Identity, PolkadotXcm, Proxy, Utility}` creates a path where identity-related state changes and asset-moving calls disagree about the effective owner or beneficiary, breaking the invariant that signed users must never reach registrar or admin-like effects through batching, proxying, or XCM aliasing, and leading to high - unauthorized execution against another account or beneficiary?

## Target
- File/function: `system-parachains/people/people-kusama/src/lib.rs` :: `construct_runtime! / RuntimeCall::{Identity, PolkadotXcm, Proxy, Utility}`
- Entrypoint: `Proxy::proxy` / `Multisig::as_multi` / `Utility::batch_all`
- Attacker controls: batched updates that mutate both identity deposits and transferable balances before finalization
- Exploit idea: creates a path where identity-related state changes and asset-moving calls disagree about the effective owner or beneficiary
- Invariant to test: signed users must never reach registrar or admin-like effects through batching, proxying, or XCM aliasing
- Expected Immunefi impact: High - unauthorized execution against another account or beneficiary
- Fast validation: runtime integration test around identity set, clear, sub-account, and refund sequencing
