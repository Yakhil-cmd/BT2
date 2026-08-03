# Q1036: pool-versus-staking split via xcmpallet execute send limited on Kusama Relay runtime

## Question
Can an unprivileged attacker enter through `XcmPallet::{execute, send, limited_reserve_transfer_assets, teleport_assets}` on Kusama Relay runtime and control a batched combination of proxy, multisig, XCM, and staking-related calls in one transaction so that `impl pallet_staking::Config` forces a state transition that should be blocked by lock, freeze, pending-unlock, or announcement rules, breaking the invariant that one pool share, claim, contribution, or unlock chunk may only be exited or consumed once, and leading to critical - permanent freeze of user funds?

## Target
- File/function: `relay/kusama/src/lib.rs` :: `impl pallet_staking::Config`
- Entrypoint: `XcmPallet::{execute, send, limited_reserve_transfer_assets, teleport_assets}`
- Attacker controls: a batched combination of proxy, multisig, XCM, and staking-related calls in one transaction
- Exploit idea: forces a state transition that should be blocked by lock, freeze, pending-unlock, or announcement rules
- Invariant to test: one pool share, claim, contribution, or unlock chunk may only be exited or consumed once
- Expected Immunefi impact: Critical - permanent freeze of user funds
- Fast validation: stateful fuzz test comparing pre and post balances, holds, reserves, and points
