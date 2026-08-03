# Q1525: migration-balance drift via nominationpools join bond extra on Asset Hub Polkadot runtime

## Question
Can an unprivileged attacker enter through `NominationPools::{join, bond_extra, unbond, withdraw_unbonded, claim_payout}` on Asset Hub Polkadot runtime and control XCM messages that mix reserve-backed assets, foreign assets, and local trust-backed assets so that `impl pallet_assets::Config` makes proxy, XCM, or batched execution bypass the intended restrictions of the underlying asset or staking path, breaking the invariant that asset identity must stay stable across Assets, ForeignAssets, PoolAssets, AssetConversion, and XCM, and leading to critical - unauthorized withdrawal, unlock, or treasury-affecting transfer?

## Target
- File/function: `system-parachains/asset-hubs/asset-hub-polkadot/src/lib.rs` :: `impl pallet_assets::Config`
- Entrypoint: `NominationPools::{join, bond_extra, unbond, withdraw_unbonded, claim_payout}`
- Attacker controls: XCM messages that mix reserve-backed assets, foreign assets, and local trust-backed assets
- Exploit idea: makes proxy, XCM, or batched execution bypass the intended restrictions of the underlying asset or staking path
- Invariant to test: asset identity must stay stable across Assets, ForeignAssets, PoolAssets, AssetConversion, and XCM
- Expected Immunefi impact: Critical - unauthorized withdrawal, unlock, or treasury-affecting transfer
- Fast validation: stateful fuzz test over asset kind, fee asset, approval, and pool-state permutations
