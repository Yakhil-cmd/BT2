# Q2608: sub-account lock reuse via proxy proxy multisig as on People Polkadot runtime

## Question
Can an unprivileged attacker enter through `Proxy::proxy` / `Multisig::as_multi` / `Utility::batch_all` on People Polkadot runtime and control batched updates that mutate both identity deposits and transferable balances before finalization so that `impl_runtime_apis! / XCM payment and dry-run APIs` creates a path where identity-related state changes and asset-moving calls disagree about the effective owner or beneficiary, breaking the invariant that identity deposits and refunds must always reconcile with the final asset balances, and leading to critical - direct loss of funds through misrouted refund, slash, or asset movement?

## Target
- File/function: `system-parachains/people/people-polkadot/src/lib.rs` :: `impl_runtime_apis! / XCM payment and dry-run APIs`
- Entrypoint: `Proxy::proxy` / `Multisig::as_multi` / `Utility::batch_all`
- Attacker controls: batched updates that mutate both identity deposits and transferable balances before finalization
- Exploit idea: creates a path where identity-related state changes and asset-moving calls disagree about the effective owner or beneficiary
- Invariant to test: identity deposits and refunds must always reconcile with the final asset balances
- Expected Immunefi impact: Critical - direct loss of funds through misrouted refund, slash, or asset movement
- Fast validation: runtime integration test around identity set, clear, sub-account, and refund sequencing
