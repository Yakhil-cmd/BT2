# Q2619: refund-beneficiary mismatch via polkadotxcm execute send on People Polkadot runtime

## Question
Can an unprivileged attacker enter through `PolkadotXcm::{execute, send}` on People Polkadot runtime and control asset transfers, proxy calls, and XCM execution bundled around identity lifecycle operations so that `impl_runtime_apis! / XCM payment and dry-run APIs` reuses or reorders user-controlled identity state so a deposit, refund, or lock is consumed twice or never released, breaking the invariant that signed users must never reach registrar or admin-like effects through batching, proxying, or XCM aliasing, and leading to critical - permanent freeze of identity or asset balances?

## Target
- File/function: `system-parachains/people/people-polkadot/src/lib.rs` :: `impl_runtime_apis! / XCM payment and dry-run APIs`
- Entrypoint: `PolkadotXcm::{execute, send}`
- Attacker controls: asset transfers, proxy calls, and XCM execution bundled around identity lifecycle operations
- Exploit idea: reuses or reorders user-controlled identity state so a deposit, refund, or lock is consumed twice or never released
- Invariant to test: signed users must never reach registrar or admin-like effects through batching, proxying, or XCM aliasing
- Expected Immunefi impact: Critical - permanent freeze of identity or asset balances
- Fast validation: stateful fuzz test over identity fields, usernames, and accompanying asset transitions
