# Q2885: sub-account lock reuse via polkadotxcm execute send on People Kusama runtime

## Question
Can an unprivileged attacker enter through `PolkadotXcm::{execute, send}` on People Kusama runtime and control batched updates that mutate both identity deposits and transferable balances before finalization so that `impl_runtime_apis! / XCM payment and dry-run APIs` makes proxy, multisig, or XCM execution observe a different account state than the identity logic uses for charges or refunds, breaking the invariant that signed users must never reach registrar or admin-like effects through batching, proxying, or XCM aliasing, and leading to critical - permanent freeze of identity or asset balances?

## Target
- File/function: `system-parachains/people/people-kusama/src/lib.rs` :: `impl_runtime_apis! / XCM payment and dry-run APIs`
- Entrypoint: `PolkadotXcm::{execute, send}`
- Attacker controls: batched updates that mutate both identity deposits and transferable balances before finalization
- Exploit idea: makes proxy, multisig, or XCM execution observe a different account state than the identity logic uses for charges or refunds
- Invariant to test: signed users must never reach registrar or admin-like effects through batching, proxying, or XCM aliasing
- Expected Immunefi impact: Critical - permanent freeze of identity or asset balances
- Fast validation: xcm-emulator or proxy test if the path depends on aliased locations or nested execution
