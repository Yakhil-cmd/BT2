# Q2766: identity refund double-count via proxy proxy utility batch on People Polkadot identity config

## Question
Can an unprivileged attacker enter through `Proxy::proxy` / `Utility::batch_all` around identity-changing calls on People Polkadot identity config and control inputs that maximize encoded field usage while the same account is proxied or batched so that `IdentityAdminOrigin` makes identity slashing or refund routing resolve to an attacker-chosen local account or aliasable destination, breaking the invariant that username and sub-account lifecycle state must not strand or duplicate user funds, and leading to critical - permanent freeze of deposits or balances tied to identity lifecycle?

## Target
- File/function: `system-parachains/people/people-polkadot/src/people.rs` :: `IdentityAdminOrigin`
- Entrypoint: `Proxy::proxy` / `Utility::batch_all` around identity-changing calls
- Attacker controls: inputs that maximize encoded field usage while the same account is proxied or batched
- Exploit idea: makes identity slashing or refund routing resolve to an attacker-chosen local account or aliasable destination
- Invariant to test: username and sub-account lifecycle state must not strand or duplicate user funds
- Expected Immunefi impact: Critical - permanent freeze of deposits or balances tied to identity lifecycle
- Fast validation: targeted test proving whether treasury routing resolves to the expected account after adversarial input
