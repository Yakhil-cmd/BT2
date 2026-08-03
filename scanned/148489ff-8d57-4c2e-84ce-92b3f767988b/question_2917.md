# Q2917: refund-beneficiary mismatch via proxy proxy multisig as on People Kusama runtime

## Question
Can an unprivileged attacker enter through `Proxy::proxy` / `Multisig::as_multi` / `Utility::batch_all` on People Kusama runtime and control batched updates that mutate both identity deposits and transferable balances before finalization so that `impl_runtime_apis! / XCM payment and dry-run APIs` creates a path where identity-related state changes and asset-moving calls disagree about the effective owner or beneficiary, breaking the invariant that identity slashing and treasury routing must not leak funds to attacker-chosen beneficiaries, and leading to critical - permanent freeze of identity or asset balances?

## Target
- File/function: `system-parachains/people/people-kusama/src/lib.rs` :: `impl_runtime_apis! / XCM payment and dry-run APIs`
- Entrypoint: `Proxy::proxy` / `Multisig::as_multi` / `Utility::batch_all`
- Attacker controls: batched updates that mutate both identity deposits and transferable balances before finalization
- Exploit idea: creates a path where identity-related state changes and asset-moving calls disagree about the effective owner or beneficiary
- Invariant to test: identity slashing and treasury routing must not leak funds to attacker-chosen beneficiaries
- Expected Immunefi impact: Critical - permanent freeze of identity or asset balances
- Fast validation: xcm-emulator or proxy test if the path depends on aliased locations or nested execution
