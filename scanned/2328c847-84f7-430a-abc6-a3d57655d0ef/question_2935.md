# Q2935: sub-account lock reuse via proxy proxy multisig as on People Kusama runtime

## Question
Can an unprivileged attacker enter through `Proxy::proxy` / `Multisig::as_multi` / `Utility::batch_all` on People Kusama runtime and control identity fields, username state, sub-account lists, and deposits packed into one signed flow so that `impl_runtime_apis! / XCM payment and dry-run APIs` reuses or reorders user-controlled identity state so a deposit, refund, or lock is consumed twice or never released, breaking the invariant that signed users must never reach registrar or admin-like effects through batching, proxying, or XCM aliasing, and leading to critical - permanent freeze of identity or asset balances?

## Target
- File/function: `system-parachains/people/people-kusama/src/lib.rs` :: `impl_runtime_apis! / XCM payment and dry-run APIs`
- Entrypoint: `Proxy::proxy` / `Multisig::as_multi` / `Utility::batch_all`
- Attacker controls: identity fields, username state, sub-account lists, and deposits packed into one signed flow
- Exploit idea: reuses or reorders user-controlled identity state so a deposit, refund, or lock is consumed twice or never released
- Invariant to test: signed users must never reach registrar or admin-like effects through batching, proxying, or XCM aliasing
- Expected Immunefi impact: Critical - permanent freeze of identity or asset balances
- Fast validation: runtime integration test around identity set, clear, sub-account, and refund sequencing
