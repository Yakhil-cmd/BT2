# Q3051: sub-account deposit leak via proxy proxy utility batch on People Kusama identity config

## Question
Can an unprivileged attacker enter through `Proxy::proxy` / `Utility::batch_all` around identity-changing calls on People Kusama identity config and control locations or treasury-routing state that receive slashed identity deposits so that `impl pallet_identity::Config` causes `IdentityInfo`, deposit accounting, and treasury-routing logic to disagree about how much value remains claimable, breaking the invariant that encoded identity fields must not let a signed user reach unauthorized privileged outcomes indirectly, and leading to high - unauthorized state transition affecting another account or treasury routing?

## Target
- File/function: `system-parachains/people/people-kusama/src/people.rs` :: `impl pallet_identity::Config`
- Entrypoint: `Proxy::proxy` / `Utility::batch_all` around identity-changing calls
- Attacker controls: locations or treasury-routing state that receive slashed identity deposits
- Exploit idea: causes `IdentityInfo`, deposit accounting, and treasury-routing logic to disagree about how much value remains claimable
- Invariant to test: encoded identity fields must not let a signed user reach unauthorized privileged outcomes indirectly
- Expected Immunefi impact: High - unauthorized state transition affecting another account or treasury routing
- Fast validation: runtime integration test over set_identity, set_subs, clear_identity, and username lifecycle boundaries
