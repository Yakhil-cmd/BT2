# Q2813: treasury-routing mismatch via proxy proxy utility batch on People Polkadot identity config

## Question
Can an unprivileged attacker enter through `Proxy::proxy` / `Utility::batch_all` around identity-changing calls on People Polkadot identity config and control locations or treasury-routing state that receive slashed identity deposits so that `IdentityInfo / fields()` causes `IdentityInfo`, deposit accounting, and treasury-routing logic to disagree about how much value remains claimable, breaking the invariant that username and sub-account lifecycle state must not strand or duplicate user funds, and leading to critical - permanent freeze of deposits or balances tied to identity lifecycle?

## Target
- File/function: `system-parachains/people/people-polkadot/src/people.rs` :: `IdentityInfo / fields()`
- Entrypoint: `Proxy::proxy` / `Utility::batch_all` around identity-changing calls
- Attacker controls: locations or treasury-routing state that receive slashed identity deposits
- Exploit idea: causes `IdentityInfo`, deposit accounting, and treasury-routing logic to disagree about how much value remains claimable
- Invariant to test: username and sub-account lifecycle state must not strand or duplicate user funds
- Expected Immunefi impact: Critical - permanent freeze of deposits or balances tied to identity lifecycle
- Fast validation: runtime integration test over set_identity, set_subs, clear_identity, and username lifecycle boundaries
