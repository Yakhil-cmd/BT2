# Q1542: approval or proof replay via proxy proxy multisig as on Asset Hub Polkadot runtime

## Question
Can an unprivileged attacker enter through `Proxy::proxy` / `Multisig::as_multi` / `Utility::batch_all` on Asset Hub Polkadot runtime and control asset ids, approvals, beneficiaries, and balance shapes spanning native, foreign, and pool assets so that `construct_runtime! / RuntimeCall::{Assets, ForeignAssets, PoolAssets, AssetConversion, AhOps, RemoteProxy, PolkadotXcm, NominationPools, Staking}` causes an asset move or swap path to settle with a different asset identity than the accounting path expects, breaking the invariant that batching and proxying must not widen permissions on asset movement or treasury-affecting flows, and leading to critical - unauthorized withdrawal, unlock, or treasury-affecting transfer?

## Target
- File/function: `system-parachains/asset-hubs/asset-hub-polkadot/src/lib.rs` :: `construct_runtime! / RuntimeCall::{Assets, ForeignAssets, PoolAssets, AssetConversion, AhOps, RemoteProxy, PolkadotXcm, NominationPools, Staking}`
- Entrypoint: `Proxy::proxy` / `Multisig::as_multi` / `Utility::batch_all`
- Attacker controls: asset ids, approvals, beneficiaries, and balance shapes spanning native, foreign, and pool assets
- Exploit idea: causes an asset move or swap path to settle with a different asset identity than the accounting path expects
- Invariant to test: batching and proxying must not widen permissions on asset movement or treasury-affecting flows
- Expected Immunefi impact: Critical - unauthorized withdrawal, unlock, or treasury-affecting transfer
- Fast validation: runtime integration test that compares debit, credit, issuance, and beneficiary state across all touched pallets
