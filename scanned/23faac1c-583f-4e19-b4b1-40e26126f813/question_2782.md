# Q2782: identity refund double-count via proxy proxy utility batch on People Polkadot identity config

## Question
Can an unprivileged attacker enter through `Proxy::proxy` / `Utility::batch_all` around identity-changing calls on People Polkadot identity config and control username expiration and grace-period boundaries combined with balance-moving calls so that `IdentityInfo / fields()` lets a user reclaim or avoid an identity-related deposit after the chain has already treated it as consumed, breaking the invariant that treasury routing for slashed deposits must never be attacker-controlled from a signed path, and leading to critical - permanent freeze of deposits or balances tied to identity lifecycle?

## Target
- File/function: `system-parachains/people/people-polkadot/src/people.rs` :: `IdentityInfo / fields()`
- Entrypoint: `Proxy::proxy` / `Utility::batch_all` around identity-changing calls
- Attacker controls: username expiration and grace-period boundaries combined with balance-moving calls
- Exploit idea: lets a user reclaim or avoid an identity-related deposit after the chain has already treated it as consumed
- Invariant to test: treasury routing for slashed deposits must never be attacker-controlled from a signed path
- Expected Immunefi impact: Critical - permanent freeze of deposits or balances tied to identity lifecycle
- Fast validation: stateful fuzz test for repeated identity mutation with balance assertions before and after refund/slash
