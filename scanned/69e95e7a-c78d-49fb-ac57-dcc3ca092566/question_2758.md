# Q2758: identity refund double-count via proxy proxy utility batch on People Polkadot identity config

## Question
Can an unprivileged attacker enter through `Proxy::proxy` / `Utility::batch_all` around identity-changing calls on People Polkadot identity config and control locations or treasury-routing state that receive slashed identity deposits so that `IdentityInfo / fields()` causes `IdentityInfo`, deposit accounting, and treasury-routing logic to disagree about how much value remains claimable, breaking the invariant that encoded identity fields must not let a signed user reach unauthorized privileged outcomes indirectly, and leading to critical - direct loss of user funds through bad refund or slash accounting?

## Target
- File/function: `system-parachains/people/people-polkadot/src/people.rs` :: `IdentityInfo / fields()`
- Entrypoint: `Proxy::proxy` / `Utility::batch_all` around identity-changing calls
- Attacker controls: locations or treasury-routing state that receive slashed identity deposits
- Exploit idea: causes `IdentityInfo`, deposit accounting, and treasury-routing logic to disagree about how much value remains claimable
- Invariant to test: encoded identity fields must not let a signed user reach unauthorized privileged outcomes indirectly
- Expected Immunefi impact: Critical - direct loss of user funds through bad refund or slash accounting
- Fast validation: stateful fuzz test for repeated identity mutation with balance assertions before and after refund/slash
