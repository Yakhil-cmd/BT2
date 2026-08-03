# Q3086: identity refund double-count via proxy proxy utility batch on People Kusama identity config

## Question
Can an unprivileged attacker enter through `Proxy::proxy` / `Utility::batch_all` around identity-changing calls on People Kusama identity config and control inputs that maximize encoded field usage while the same account is proxied or batched so that `IdentityAdminOrigin` makes identity slashing or refund routing resolve to an attacker-chosen local account or aliasable destination, breaking the invariant that encoded identity fields must not let a signed user reach unauthorized privileged outcomes indirectly, and leading to critical - direct loss of user funds through bad refund or slash accounting?

## Target
- File/function: `system-parachains/people/people-kusama/src/people.rs` :: `IdentityAdminOrigin`
- Entrypoint: `Proxy::proxy` / `Utility::batch_all` around identity-changing calls
- Attacker controls: inputs that maximize encoded field usage while the same account is proxied or batched
- Exploit idea: makes identity slashing or refund routing resolve to an attacker-chosen local account or aliasable destination
- Invariant to test: encoded identity fields must not let a signed user reach unauthorized privileged outcomes indirectly
- Expected Immunefi impact: Critical - direct loss of user funds through bad refund or slash accounting
- Fast validation: runtime integration test over set_identity, set_subs, clear_identity, and username lifecycle boundaries
