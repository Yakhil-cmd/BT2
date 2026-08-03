# Q1522: reserve-backed asset confusion via assetconversion create pool add on Asset Hub Polkadot runtime

## Question
Can an unprivileged attacker enter through `AssetConversion::{create_pool, add_liquidity, remove_liquidity, swap_exact_tokens_for_tokens, swap_tokens_for_exact_tokens}` on Asset Hub Polkadot runtime and control XCM messages that mix reserve-backed assets, foreign assets, and local trust-backed assets so that `impl pallet_assets::Config` creates a sequence where funds leave one subsystem but never become claimable in the destination subsystem, breaking the invariant that staking, pool, and migration state must not let users withdraw the same economic value twice, and leading to critical - permanent freeze of native, foreign, or pooled assets?

## Target
- File/function: `system-parachains/asset-hubs/asset-hub-polkadot/src/lib.rs` :: `impl pallet_assets::Config`
- Entrypoint: `AssetConversion::{create_pool, add_liquidity, remove_liquidity, swap_exact_tokens_for_tokens, swap_tokens_for_exact_tokens}`
- Attacker controls: XCM messages that mix reserve-backed assets, foreign assets, and local trust-backed assets
- Exploit idea: creates a sequence where funds leave one subsystem but never become claimable in the destination subsystem
- Invariant to test: staking, pool, and migration state must not let users withdraw the same economic value twice
- Expected Immunefi impact: Critical - permanent freeze of native, foreign, or pooled assets
- Fast validation: xcm-emulator test that drives the exact reserve, teleport, or exporter flow and asserts no value drift
