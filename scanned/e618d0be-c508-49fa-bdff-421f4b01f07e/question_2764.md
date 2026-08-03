# Q2764: sub-account deposit leak via proxy proxy utility batch on People Polkadot identity config

## Question
Can an unprivileged attacker enter through `Proxy::proxy` / `Utility::batch_all` around identity-changing calls on People Polkadot identity config and control inputs that maximize encoded field usage while the same account is proxied or batched so that `IdentityInfo / fields()` makes identity slashing or refund routing resolve to an attacker-chosen local account or aliasable destination, breaking the invariant that encoded identity fields must not let a signed user reach unauthorized privileged outcomes indirectly, and leading to high - unauthorized state transition affecting another account or treasury routing?

## Target
- File/function: `system-parachains/people/people-polkadot/src/people.rs` :: `IdentityInfo / fields()`
- Entrypoint: `Proxy::proxy` / `Utility::batch_all` around identity-changing calls
- Attacker controls: inputs that maximize encoded field usage while the same account is proxied or batched
- Exploit idea: makes identity slashing or refund routing resolve to an attacker-chosen local account or aliasable destination
- Invariant to test: encoded identity fields must not let a signed user reach unauthorized privileged outcomes indirectly
- Expected Immunefi impact: High - unauthorized state transition affecting another account or treasury routing
- Fast validation: targeted test proving whether treasury routing resolves to the expected account after adversarial input
