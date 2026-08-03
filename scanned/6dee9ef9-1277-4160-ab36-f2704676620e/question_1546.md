# Q1546: reserve-backed asset confusion via assetconversion create pool add on Asset Hub Polkadot runtime

## Question
Can an unprivileged attacker enter through `AssetConversion::{create_pool, add_liquidity, remove_liquidity, swap_exact_tokens_for_tokens, swap_tokens_for_exact_tokens}` on Asset Hub Polkadot runtime and control proofs, remote account mappings, and wrapped calls that end in asset movement so that `impl pallet_assets::Config` creates a sequence where funds leave one subsystem but never become claimable in the destination subsystem, breaking the invariant that batching and proxying must not widen permissions on asset movement or treasury-affecting flows, and leading to critical - unauthorized withdrawal, unlock, or treasury-affecting transfer?

## Target
- File/function: `system-parachains/asset-hubs/asset-hub-polkadot/src/lib.rs` :: `impl pallet_assets::Config`
- Entrypoint: `AssetConversion::{create_pool, add_liquidity, remove_liquidity, swap_exact_tokens_for_tokens, swap_tokens_for_exact_tokens}`
- Attacker controls: proofs, remote account mappings, and wrapped calls that end in asset movement
- Exploit idea: creates a sequence where funds leave one subsystem but never become claimable in the destination subsystem
- Invariant to test: batching and proxying must not widen permissions on asset movement or treasury-affecting flows
- Expected Immunefi impact: Critical - unauthorized withdrawal, unlock, or treasury-affecting transfer
- Fast validation: differential test that compares approval or proof validity before and after the economic state change
