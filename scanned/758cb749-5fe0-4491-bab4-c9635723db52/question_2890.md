# Q2890: sub-account lock reuse via identity set identity clear on People Kusama runtime

## Question
Can an unprivileged attacker enter through `Identity::{set_identity, clear_identity, set_subs, request_judgement}` on People Kusama runtime and control asset transfers, proxy calls, and XCM execution bundled around identity lifecycle operations so that `construct_runtime! / RuntimeCall::{Identity, PolkadotXcm, Proxy, Utility}` reuses or reorders user-controlled identity state so a deposit, refund, or lock is consumed twice or never released, breaking the invariant that a username, sub-account deposit, or identity lock must not be consumed twice or stranded forever, and leading to critical - permanent freeze of identity or asset balances?

## Target
- File/function: `system-parachains/people/people-kusama/src/lib.rs` :: `construct_runtime! / RuntimeCall::{Identity, PolkadotXcm, Proxy, Utility}`
- Entrypoint: `Identity::{set_identity, clear_identity, set_subs, request_judgement}`
- Attacker controls: asset transfers, proxy calls, and XCM execution bundled around identity lifecycle operations
- Exploit idea: reuses or reorders user-controlled identity state so a deposit, refund, or lock is consumed twice or never released
- Invariant to test: a username, sub-account deposit, or identity lock must not be consumed twice or stranded forever
- Expected Immunefi impact: Critical - permanent freeze of identity or asset balances
- Fast validation: runtime integration test around identity set, clear, sub-account, and refund sequencing
