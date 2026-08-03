# Q2770: identity refund double-count via proxy proxy utility batch on People Polkadot identity config

## Question
Can an unprivileged attacker enter through `Proxy::proxy` / `Utility::batch_all` around identity-changing calls on People Polkadot identity config and control inputs that maximize encoded field usage while the same account is proxied or batched so that `IdentityInfo / fields()` lets a user reclaim or avoid an identity-related deposit after the chain has already treated it as consumed, breaking the invariant that identity-related deposits must be debited, refunded, or slashed exactly once, and leading to high - unauthorized state transition affecting another account or treasury routing?

## Target
- File/function: `system-parachains/people/people-polkadot/src/people.rs` :: `IdentityInfo / fields()`
- Entrypoint: `Proxy::proxy` / `Utility::batch_all` around identity-changing calls
- Attacker controls: inputs that maximize encoded field usage while the same account is proxied or batched
- Exploit idea: lets a user reclaim or avoid an identity-related deposit after the chain has already treated it as consumed
- Invariant to test: identity-related deposits must be debited, refunded, or slashed exactly once
- Expected Immunefi impact: High - unauthorized state transition affecting another account or treasury routing
- Fast validation: stateful fuzz test for repeated identity mutation with balance assertions before and after refund/slash
