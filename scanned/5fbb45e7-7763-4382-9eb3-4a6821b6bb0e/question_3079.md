# Q3079: sub-account deposit leak via proxy proxy utility batch on People Kusama identity config

## Question
Can an unprivileged attacker enter through `Proxy::proxy` / `Utility::batch_all` around identity-changing calls on People Kusama identity config and control locations or treasury-routing state that receive slashed identity deposits so that `impl pallet_identity::Config` lets a user reclaim or avoid an identity-related deposit after the chain has already treated it as consumed, breaking the invariant that identity-related deposits must be debited, refunded, or slashed exactly once, and leading to critical - direct loss of user funds through bad refund or slash accounting?

## Target
- File/function: `system-parachains/people/people-kusama/src/people.rs` :: `impl pallet_identity::Config`
- Entrypoint: `Proxy::proxy` / `Utility::batch_all` around identity-changing calls
- Attacker controls: locations or treasury-routing state that receive slashed identity deposits
- Exploit idea: lets a user reclaim or avoid an identity-related deposit after the chain has already treated it as consumed
- Invariant to test: identity-related deposits must be debited, refunded, or slashed exactly once
- Expected Immunefi impact: Critical - direct loss of user funds through bad refund or slash accounting
- Fast validation: runtime integration test over set_identity, set_subs, clear_identity, and username lifecycle boundaries
