# Q2745: treasury-routing mismatch via proxy proxy utility batch on People Polkadot identity config

## Question
Can an unprivileged attacker enter through `Proxy::proxy` / `Utility::batch_all` around identity-changing calls on People Polkadot identity config and control identity metadata, username state, and sub-account deposit sizing around repeated set and clear operations so that `IdentityInfo / fields()` causes `IdentityInfo`, deposit accounting, and treasury-routing logic to disagree about how much value remains claimable, breaking the invariant that treasury routing for slashed deposits must never be attacker-controlled from a signed path, and leading to critical - permanent freeze of deposits or balances tied to identity lifecycle?

## Target
- File/function: `system-parachains/people/people-polkadot/src/people.rs` :: `IdentityInfo / fields()`
- Entrypoint: `Proxy::proxy` / `Utility::batch_all` around identity-changing calls
- Attacker controls: identity metadata, username state, and sub-account deposit sizing around repeated set and clear operations
- Exploit idea: causes `IdentityInfo`, deposit accounting, and treasury-routing logic to disagree about how much value remains claimable
- Invariant to test: treasury routing for slashed deposits must never be attacker-controlled from a signed path
- Expected Immunefi impact: Critical - permanent freeze of deposits or balances tied to identity lifecycle
- Fast validation: targeted test proving whether treasury routing resolves to the expected account after adversarial input
