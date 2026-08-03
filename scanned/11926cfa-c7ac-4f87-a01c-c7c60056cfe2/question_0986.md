# Q986: double-withdraw edge via xcmpallet execute send limited on Kusama Relay runtime

## Question
Can an unprivileged attacker enter through `XcmPallet::{execute, send, limited_reserve_transfer_assets, teleport_assets}` on Kusama Relay runtime and control a batched combination of proxy, multisig, XCM, and staking-related calls in one transaction so that `impl pallet_nomination_pools::Config` forces a state transition that should be blocked by lock, freeze, pending-unlock, or announcement rules, breaking the invariant that unlocking state, holds, and reserves must stay consistent across all touched pallets, and leading to critical - direct loss of funds or unbacked withdrawal?

## Target
- File/function: `relay/kusama/src/lib.rs` :: `impl pallet_nomination_pools::Config`
- Entrypoint: `XcmPallet::{execute, send, limited_reserve_transfer_assets, teleport_assets}`
- Attacker controls: a batched combination of proxy, multisig, XCM, and staking-related calls in one transaction
- Exploit idea: forces a state transition that should be blocked by lock, freeze, pending-unlock, or announcement rules
- Invariant to test: unlocking state, holds, and reserves must stay consistent across all touched pallets
- Expected Immunefi impact: Critical - direct loss of funds or unbacked withdrawal
- Fast validation: stateful fuzz test comparing pre and post balances, holds, reserves, and points
