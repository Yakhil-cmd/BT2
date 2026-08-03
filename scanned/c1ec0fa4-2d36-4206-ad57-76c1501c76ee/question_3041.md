# Q3041: treasury-routing mismatch via identity set identity clear on People Kusama identity config

## Question
Can an unprivileged attacker enter through `Identity::{set_identity, clear_identity, set_subs, request_judgement}` on People Kusama identity config and control identity metadata, username state, and sub-account deposit sizing around repeated set and clear operations so that `IdentityAdminOrigin` makes identity slashing or refund routing resolve to an attacker-chosen local account or aliasable destination, breaking the invariant that treasury routing for slashed deposits must never be attacker-controlled from a signed path, and leading to critical - permanent freeze of deposits or balances tied to identity lifecycle?

## Target
- File/function: `system-parachains/people/people-kusama/src/people.rs` :: `IdentityAdminOrigin`
- Entrypoint: `Identity::{set_identity, clear_identity, set_subs, request_judgement}`
- Attacker controls: identity metadata, username state, and sub-account deposit sizing around repeated set and clear operations
- Exploit idea: makes identity slashing or refund routing resolve to an attacker-chosen local account or aliasable destination
- Invariant to test: treasury routing for slashed deposits must never be attacker-controlled from a signed path
- Expected Immunefi impact: Critical - permanent freeze of deposits or balances tied to identity lifecycle
- Fast validation: stateful fuzz test for repeated identity mutation with balance assertions before and after refund/slash
