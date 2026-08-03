# Q992: unlock-ordering mismatch via staking bond unbond rebond on Kusama Relay runtime

## Question
Can an unprivileged attacker enter through `Staking::{bond, unbond, rebond, nominate, payout_stakers}` on Kusama Relay runtime and control a batched combination of proxy, multisig, XCM, and staking-related calls in one transaction so that `construct_runtime! / RuntimeCall::{Staking, NominationPools, Claims, Crowdloan, XcmPallet, Proxy, Utility}` makes two runtime subsystems disagree about the same user's balance, points, claimability, or unlocking state, breaking the invariant that unlocking state, holds, and reserves must stay consistent across all touched pallets, and leading to high - network-wide halt or stuck critical queue?

## Target
- File/function: `relay/kusama/src/lib.rs` :: `construct_runtime! / RuntimeCall::{Staking, NominationPools, Claims, Crowdloan, XcmPallet, Proxy, Utility}`
- Entrypoint: `Staking::{bond, unbond, rebond, nominate, payout_stakers}`
- Attacker controls: a batched combination of proxy, multisig, XCM, and staking-related calls in one transaction
- Exploit idea: makes two runtime subsystems disagree about the same user's balance, points, claimability, or unlocking state
- Invariant to test: unlocking state, holds, and reserves must stay consistent across all touched pallets
- Expected Immunefi impact: High - network-wide halt or stuck critical queue
- Fast validation: stateful fuzz test comparing pre and post balances, holds, reserves, and points
