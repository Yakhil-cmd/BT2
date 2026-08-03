# Q1470: approval or proof replay via nominationpools join bond extra on Asset Hub Polkadot runtime

## Question
Can an unprivileged attacker enter through `NominationPools::{join, bond_extra, unbond, withdraw_unbonded, claim_payout}` on Asset Hub Polkadot runtime and control asset ids, approvals, beneficiaries, and balance shapes spanning native, foreign, and pool assets so that `construct_runtime! / RuntimeCall::{Assets, ForeignAssets, PoolAssets, AssetConversion, AhOps, RemoteProxy, PolkadotXcm, NominationPools, Staking}` causes an asset move or swap path to settle with a different asset identity than the accounting path expects, breaking the invariant that asset identity must stay stable across Assets, ForeignAssets, PoolAssets, AssetConversion, and XCM, and leading to critical - unauthorized withdrawal, unlock, or treasury-affecting transfer?

## Target
- File/function: `system-parachains/asset-hubs/asset-hub-polkadot/src/lib.rs` :: `construct_runtime! / RuntimeCall::{Assets, ForeignAssets, PoolAssets, AssetConversion, AhOps, RemoteProxy, PolkadotXcm, NominationPools, Staking}`
- Entrypoint: `NominationPools::{join, bond_extra, unbond, withdraw_unbonded, claim_payout}`
- Attacker controls: asset ids, approvals, beneficiaries, and balance shapes spanning native, foreign, and pool assets
- Exploit idea: causes an asset move or swap path to settle with a different asset identity than the accounting path expects
- Invariant to test: asset identity must stay stable across Assets, ForeignAssets, PoolAssets, AssetConversion, and XCM
- Expected Immunefi impact: Critical - unauthorized withdrawal, unlock, or treasury-affecting transfer
- Fast validation: stateful fuzz test over asset kind, fee asset, approval, and pool-state permutations
