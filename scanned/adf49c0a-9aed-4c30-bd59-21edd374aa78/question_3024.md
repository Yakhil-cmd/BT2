# Q3024: identity refund double-count via proxy proxy utility batch on People Kusama identity config

## Question
Can an unprivileged attacker enter through `Proxy::proxy` / `Utility::batch_all` around identity-changing calls on People Kusama identity config and control identity metadata, username state, and sub-account deposit sizing around repeated set and clear operations so that `IdentityInfo / fields()` lets a user reclaim or avoid an identity-related deposit after the chain has already treated it as consumed, breaking the invariant that username and sub-account lifecycle state must not strand or duplicate user funds, and leading to high - unauthorized state transition affecting another account or treasury routing?

## Target
- File/function: `system-parachains/people/people-kusama/src/people.rs` :: `IdentityInfo / fields()`
- Entrypoint: `Proxy::proxy` / `Utility::batch_all` around identity-changing calls
- Attacker controls: identity metadata, username state, and sub-account deposit sizing around repeated set and clear operations
- Exploit idea: lets a user reclaim or avoid an identity-related deposit after the chain has already treated it as consumed
- Invariant to test: username and sub-account lifecycle state must not strand or duplicate user funds
- Expected Immunefi impact: High - unauthorized state transition affecting another account or treasury routing
- Fast validation: targeted test proving whether treasury routing resolves to the expected account after adversarial input
