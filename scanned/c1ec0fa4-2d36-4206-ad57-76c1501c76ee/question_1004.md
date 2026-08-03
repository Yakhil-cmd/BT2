# Q1004: pool-versus-staking split via xcmpallet execute send limited on Kusama Relay runtime

## Question
Can an unprivileged attacker enter through `XcmPallet::{execute, send, limited_reserve_transfer_assets, teleport_assets}` on Kusama Relay runtime and control repeated user-triggered pool joins, exits, or payouts around reward and slash boundaries so that `impl pallet_nomination_pools::Config` makes two runtime subsystems disagree about the same user's balance, points, claimability, or unlocking state, breaking the invariant that XCM-triggered and local transitions must preserve the same accounting rules, and leading to high - network-wide halt or stuck critical queue?

## Target
- File/function: `relay/kusama/src/lib.rs` :: `impl pallet_nomination_pools::Config`
- Entrypoint: `XcmPallet::{execute, send, limited_reserve_transfer_assets, teleport_assets}`
- Attacker controls: repeated user-triggered pool joins, exits, or payouts around reward and slash boundaries
- Exploit idea: makes two runtime subsystems disagree about the same user's balance, points, claimability, or unlocking state
- Invariant to test: XCM-triggered and local transitions must preserve the same accounting rules
- Expected Immunefi impact: High - network-wide halt or stuck critical queue
- Fast validation: stateful fuzz test comparing pre and post balances, holds, reserves, and points
