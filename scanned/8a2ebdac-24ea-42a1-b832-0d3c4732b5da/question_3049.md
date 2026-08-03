# Q3049: treasury-routing mismatch via proxy proxy utility batch on People Kusama identity config

## Question
Can an unprivileged attacker enter through `Proxy::proxy` / `Utility::batch_all` around identity-changing calls on People Kusama identity config and control identity metadata, username state, and sub-account deposit sizing around repeated set and clear operations so that `IdentityAdminOrigin` causes `IdentityInfo`, deposit accounting, and treasury-routing logic to disagree about how much value remains claimable, breaking the invariant that username and sub-account lifecycle state must not strand or duplicate user funds, and leading to critical - permanent freeze of deposits or balances tied to identity lifecycle?

## Target
- File/function: `system-parachains/people/people-kusama/src/people.rs` :: `IdentityAdminOrigin`
- Entrypoint: `Proxy::proxy` / `Utility::batch_all` around identity-changing calls
- Attacker controls: identity metadata, username state, and sub-account deposit sizing around repeated set and clear operations
- Exploit idea: causes `IdentityInfo`, deposit accounting, and treasury-routing logic to disagree about how much value remains claimable
- Invariant to test: username and sub-account lifecycle state must not strand or duplicate user funds
- Expected Immunefi impact: Critical - permanent freeze of deposits or balances tied to identity lifecycle
- Fast validation: runtime integration test over set_identity, set_subs, clear_identity, and username lifecycle boundaries
