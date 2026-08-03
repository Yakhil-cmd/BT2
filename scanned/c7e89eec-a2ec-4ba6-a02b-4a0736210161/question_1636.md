# Q1636: cross-asset accounting split via nominationpools join bond extra on Asset Hub Kusama runtime

## Question
Can an unprivileged attacker enter through `NominationPools::{join, bond_extra, unbond, withdraw_unbonded, claim_payout}` on Asset Hub Kusama runtime and control XCM messages that mix reserve-backed assets, foreign assets, and local trust-backed assets so that `impl pallet_asset_conversion::Config` makes two asset subsystems disagree about which pallet owns, mints, burns, or escrows the same economic unit, breaking the invariant that staking, pool, and migration state must not let users withdraw the same economic value twice, and leading to high - severe availability loss on a critical asset-transfer or xcm path?

## Target
- File/function: `system-parachains/asset-hubs/asset-hub-kusama/src/lib.rs` :: `impl pallet_asset_conversion::Config`
- Entrypoint: `NominationPools::{join, bond_extra, unbond, withdraw_unbonded, claim_payout}`
- Attacker controls: XCM messages that mix reserve-backed assets, foreign assets, and local trust-backed assets
- Exploit idea: makes two asset subsystems disagree about which pallet owns, mints, burns, or escrows the same economic unit
- Invariant to test: staking, pool, and migration state must not let users withdraw the same economic value twice
- Expected Immunefi impact: High - severe availability loss on a critical asset-transfer or XCM path
- Fast validation: stateful fuzz test over asset kind, fee asset, approval, and pool-state permutations
