# Q1570: reserve-backed asset confusion via assetconversion create pool add on Asset Hub Polkadot runtime

## Question
Can an unprivileged attacker enter through `AssetConversion::{create_pool, add_liquidity, remove_liquidity, swap_exact_tokens_for_tokens, swap_tokens_for_exact_tokens}` on Asset Hub Polkadot runtime and control nested proxy, batch, multisig, and XCM composition around asset-moving calls so that `impl pallet_assets::Config` makes two asset subsystems disagree about which pallet owns, mints, burns, or escrows the same economic unit, breaking the invariant that asset identity must stay stable across Assets, ForeignAssets, PoolAssets, AssetConversion, and XCM, and leading to critical - direct loss of funds or unbacked asset issuance?

## Target
- File/function: `system-parachains/asset-hubs/asset-hub-polkadot/src/lib.rs` :: `impl pallet_assets::Config`
- Entrypoint: `AssetConversion::{create_pool, add_liquidity, remove_liquidity, swap_exact_tokens_for_tokens, swap_tokens_for_exact_tokens}`
- Attacker controls: nested proxy, batch, multisig, and XCM composition around asset-moving calls
- Exploit idea: makes two asset subsystems disagree about which pallet owns, mints, burns, or escrows the same economic unit
- Invariant to test: asset identity must stay stable across Assets, ForeignAssets, PoolAssets, AssetConversion, and XCM
- Expected Immunefi impact: Critical - direct loss of funds or unbacked asset issuance
- Fast validation: runtime integration test that compares debit, credit, issuance, and beneficiary state across all touched pallets
