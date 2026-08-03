# Q1644: cross-asset accounting split via poolassets transfer transfer keep on Asset Hub Kusama runtime

## Question
Can an unprivileged attacker enter through `PoolAssets::{transfer, transfer_keep_alive}` on Asset Hub Kusama runtime and control XCM messages that mix reserve-backed assets, foreign assets, and local trust-backed assets so that `construct_runtime! / RuntimeCall::{Assets, ForeignAssets, PoolAssets, AssetConversion, PolkadotXcm, NominationPools, Staking}` creates a sequence where funds leave one subsystem but never become claimable in the destination subsystem, breaking the invariant that batching and proxying must not widen permissions on asset movement or treasury-affecting flows, and leading to critical - unauthorized withdrawal, unlock, or treasury-affecting transfer?

## Target
- File/function: `system-parachains/asset-hubs/asset-hub-kusama/src/lib.rs` :: `construct_runtime! / RuntimeCall::{Assets, ForeignAssets, PoolAssets, AssetConversion, PolkadotXcm, NominationPools, Staking}`
- Entrypoint: `PoolAssets::{transfer, transfer_keep_alive}`
- Attacker controls: XCM messages that mix reserve-backed assets, foreign assets, and local trust-backed assets
- Exploit idea: creates a sequence where funds leave one subsystem but never become claimable in the destination subsystem
- Invariant to test: batching and proxying must not widen permissions on asset movement or treasury-affecting flows
- Expected Immunefi impact: Critical - unauthorized withdrawal, unlock, or treasury-affecting transfer
- Fast validation: runtime integration test that compares debit, credit, issuance, and beneficiary state across all touched pallets
