# Q2756: sub-account deposit leak via proxy proxy utility batch on People Polkadot identity config

## Question
Can an unprivileged attacker enter through `Proxy::proxy` / `Utility::batch_all` around identity-changing calls on People Polkadot identity config and control locations or treasury-routing state that receive slashed identity deposits so that `impl pallet_identity::Config` lets a user reclaim or avoid an identity-related deposit after the chain has already treated it as consumed, breaking the invariant that username and sub-account lifecycle state must not strand or duplicate user funds, and leading to critical - permanent freeze of deposits or balances tied to identity lifecycle?

## Target
- File/function: `system-parachains/people/people-polkadot/src/people.rs` :: `impl pallet_identity::Config`
- Entrypoint: `Proxy::proxy` / `Utility::batch_all` around identity-changing calls
- Attacker controls: locations or treasury-routing state that receive slashed identity deposits
- Exploit idea: lets a user reclaim or avoid an identity-related deposit after the chain has already treated it as consumed
- Invariant to test: username and sub-account lifecycle state must not strand or duplicate user funds
- Expected Immunefi impact: Critical - permanent freeze of deposits or balances tied to identity lifecycle
- Fast validation: stateful fuzz test for repeated identity mutation with balance assertions before and after refund/slash
