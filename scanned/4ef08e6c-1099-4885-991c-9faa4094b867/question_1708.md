# Q1708: cross-asset accounting split via polkadotxcm send execute transfer on Asset Hub Kusama runtime

## Question
Can an unprivileged attacker enter through `PolkadotXcm::{send, execute, transfer_assets, limited_reserve_transfer_assets}` on Asset Hub Kusama runtime and control asset ids, approvals, beneficiaries, and balance shapes spanning native, foreign, and pool assets so that `construct_runtime! / RuntimeCall::{Assets, ForeignAssets, PoolAssets, AssetConversion, PolkadotXcm, NominationPools, Staking}` makes proxy, XCM, or batched execution bypass the intended restrictions of the underlying asset or staking path, breaking the invariant that batching and proxying must not widen permissions on asset movement or treasury-affecting flows, and leading to critical - direct loss of funds or unbacked asset issuance?

## Target
- File/function: `system-parachains/asset-hubs/asset-hub-kusama/src/lib.rs` :: `construct_runtime! / RuntimeCall::{Assets, ForeignAssets, PoolAssets, AssetConversion, PolkadotXcm, NominationPools, Staking}`
- Entrypoint: `PolkadotXcm::{send, execute, transfer_assets, limited_reserve_transfer_assets}`
- Attacker controls: asset ids, approvals, beneficiaries, and balance shapes spanning native, foreign, and pool assets
- Exploit idea: makes proxy, XCM, or batched execution bypass the intended restrictions of the underlying asset or staking path
- Invariant to test: batching and proxying must not widen permissions on asset movement or treasury-affecting flows
- Expected Immunefi impact: Critical - direct loss of funds or unbacked asset issuance
- Fast validation: runtime integration test that compares debit, credit, issuance, and beneficiary state across all touched pallets
