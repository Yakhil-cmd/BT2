# Q2748: sub-account deposit leak via proxy proxy utility batch on People Polkadot identity config

## Question
Can an unprivileged attacker enter through `Proxy::proxy` / `Utility::batch_all` around identity-changing calls on People Polkadot identity config and control locations or treasury-routing state that receive slashed identity deposits so that `IdentityAdminOrigin` creates a sequencing edge where identity cleanup and concurrent value transfer leave funds permanently stranded or duplicated, breaking the invariant that encoded identity fields must not let a signed user reach unauthorized privileged outcomes indirectly, and leading to critical - direct loss of user funds through bad refund or slash accounting?

## Target
- File/function: `system-parachains/people/people-polkadot/src/people.rs` :: `IdentityAdminOrigin`
- Entrypoint: `Proxy::proxy` / `Utility::batch_all` around identity-changing calls
- Attacker controls: locations or treasury-routing state that receive slashed identity deposits
- Exploit idea: creates a sequencing edge where identity cleanup and concurrent value transfer leave funds permanently stranded or duplicated
- Invariant to test: encoded identity fields must not let a signed user reach unauthorized privileged outcomes indirectly
- Expected Immunefi impact: Critical - direct loss of user funds through bad refund or slash accounting
- Fast validation: runtime integration test over set_identity, set_subs, clear_identity, and username lifecycle boundaries
