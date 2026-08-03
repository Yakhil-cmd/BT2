# Q1467: proxy-batched asset escape via assetconversion create pool add on Asset Hub Polkadot runtime

## Question
Can an unprivileged attacker enter through `AssetConversion::{create_pool, add_liquidity, remove_liquidity, swap_exact_tokens_for_tokens, swap_tokens_for_exact_tokens}` on Asset Hub Polkadot runtime and control asset ids, approvals, beneficiaries, and balance shapes spanning native, foreign, and pool assets so that `construct_runtime! / RuntimeCall::{Assets, ForeignAssets, PoolAssets, AssetConversion, AhOps, RemoteProxy, PolkadotXcm, NominationPools, Staking}` reuses an approval, proof, or queued call after the economic precondition that justified it has changed, breaking the invariant that staking, pool, and migration state must not let users withdraw the same economic value twice, and leading to critical - permanent freeze of native, foreign, or pooled assets?

## Target
- File/function: `system-parachains/asset-hubs/asset-hub-polkadot/src/lib.rs` :: `construct_runtime! / RuntimeCall::{Assets, ForeignAssets, PoolAssets, AssetConversion, AhOps, RemoteProxy, PolkadotXcm, NominationPools, Staking}`
- Entrypoint: `AssetConversion::{create_pool, add_liquidity, remove_liquidity, swap_exact_tokens_for_tokens, swap_tokens_for_exact_tokens}`
- Attacker controls: asset ids, approvals, beneficiaries, and balance shapes spanning native, foreign, and pool assets
- Exploit idea: reuses an approval, proof, or queued call after the economic precondition that justified it has changed
- Invariant to test: staking, pool, and migration state must not let users withdraw the same economic value twice
- Expected Immunefi impact: Critical - permanent freeze of native, foreign, or pooled assets
- Fast validation: xcm-emulator test that drives the exact reserve, teleport, or exporter flow and asserts no value drift
