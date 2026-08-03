# Q3054: identity refund double-count via proxy proxy utility batch on People Kusama identity config

## Question
Can an unprivileged attacker enter through `Proxy::proxy` / `Utility::batch_all` around identity-changing calls on People Kusama identity config and control username expiration and grace-period boundaries combined with balance-moving calls so that `impl pallet_identity::Config` makes identity slashing or refund routing resolve to an attacker-chosen local account or aliasable destination, breaking the invariant that identity-related deposits must be debited, refunded, or slashed exactly once, and leading to critical - permanent freeze of deposits or balances tied to identity lifecycle?

## Target
- File/function: `system-parachains/people/people-kusama/src/people.rs` :: `impl pallet_identity::Config`
- Entrypoint: `Proxy::proxy` / `Utility::batch_all` around identity-changing calls
- Attacker controls: username expiration and grace-period boundaries combined with balance-moving calls
- Exploit idea: makes identity slashing or refund routing resolve to an attacker-chosen local account or aliasable destination
- Invariant to test: identity-related deposits must be debited, refunded, or slashed exactly once
- Expected Immunefi impact: Critical - permanent freeze of deposits or balances tied to identity lifecycle
- Fast validation: runtime integration test over set_identity, set_subs, clear_identity, and username lifecycle boundaries
