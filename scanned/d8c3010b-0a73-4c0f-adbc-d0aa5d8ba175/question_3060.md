# Q3060: username-expiry accounting drift via proxy proxy utility batch on People Kusama identity config

## Question
Can an unprivileged attacker enter through `Proxy::proxy` / `Utility::batch_all` around identity-changing calls on People Kusama identity config and control identity metadata, username state, and sub-account deposit sizing around repeated set and clear operations so that `impl pallet_identity::Config` makes identity slashing or refund routing resolve to an attacker-chosen local account or aliasable destination, breaking the invariant that treasury routing for slashed deposits must never be attacker-controlled from a signed path, and leading to high - unauthorized state transition affecting another account or treasury routing?

## Target
- File/function: `system-parachains/people/people-kusama/src/people.rs` :: `impl pallet_identity::Config`
- Entrypoint: `Proxy::proxy` / `Utility::batch_all` around identity-changing calls
- Attacker controls: identity metadata, username state, and sub-account deposit sizing around repeated set and clear operations
- Exploit idea: makes identity slashing or refund routing resolve to an attacker-chosen local account or aliasable destination
- Invariant to test: treasury routing for slashed deposits must never be attacker-controlled from a signed path
- Expected Immunefi impact: High - unauthorized state transition affecting another account or treasury routing
- Fast validation: runtime integration test over set_identity, set_subs, clear_identity, and username lifecycle boundaries
