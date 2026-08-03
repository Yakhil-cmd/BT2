# Q872: double-withdraw edge via proxy proxy multisig as on Polkadot Relay runtime

## Question
Can an unprivileged attacker enter through `Proxy::proxy` / `Multisig::as_multi` / `Utility::batch_all` on Polkadot Relay runtime and control crowdloan contribution and withdrawal timing around lease expiry and unlock boundaries so that `impl pallet_nomination_pools::Config` forces a state transition that should be blocked by lock, freeze, pending-unlock, or announcement rules, breaking the invariant that user-controlled batching must not bypass staking, pool, claim, or proxy restrictions, and leading to high - network-wide halt or stuck critical queue?

## Target
- File/function: `relay/polkadot/src/lib.rs` :: `impl pallet_nomination_pools::Config`
- Entrypoint: `Proxy::proxy` / `Multisig::as_multi` / `Utility::batch_all`
- Attacker controls: crowdloan contribution and withdrawal timing around lease expiry and unlock boundaries
- Exploit idea: forces a state transition that should be blocked by lock, freeze, pending-unlock, or announcement rules
- Invariant to test: user-controlled batching must not bypass staking, pool, claim, or proxy restrictions
- Expected Immunefi impact: High - network-wide halt or stuck critical queue
- Fast validation: stateful fuzz test comparing pre and post balances, holds, reserves, and points
