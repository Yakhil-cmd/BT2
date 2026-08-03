# Q2809: treasury-routing mismatch via proxy proxy utility batch on People Polkadot identity config

## Question
Can an unprivileged attacker enter through `Proxy::proxy` / `Utility::batch_all` around identity-changing calls on People Polkadot identity config and control locations or treasury-routing state that receive slashed identity deposits so that `IdentityAdminOrigin` lets a user reclaim or avoid an identity-related deposit after the chain has already treated it as consumed, breaking the invariant that treasury routing for slashed deposits must never be attacker-controlled from a signed path, and leading to critical - direct loss of user funds through bad refund or slash accounting?

## Target
- File/function: `system-parachains/people/people-polkadot/src/people.rs` :: `IdentityAdminOrigin`
- Entrypoint: `Proxy::proxy` / `Utility::batch_all` around identity-changing calls
- Attacker controls: locations or treasury-routing state that receive slashed identity deposits
- Exploit idea: lets a user reclaim or avoid an identity-related deposit after the chain has already treated it as consumed
- Invariant to test: treasury routing for slashed deposits must never be attacker-controlled from a signed path
- Expected Immunefi impact: Critical - direct loss of user funds through bad refund or slash accounting
- Fast validation: stateful fuzz test for repeated identity mutation with balance assertions before and after refund/slash
