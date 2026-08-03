# Q1204: origin-conversion mismatch via polkadotxcm transfer assets on Asset Hub Polkadot XCM

## Question
Can an unprivileged attacker enter through `PolkadotXcm::transfer_assets` on Asset Hub Polkadot XCM and control a location that can be interpreted differently across aliasing, account conversion, and asset transacting code so that `PoolAssetsExchanger` makes `HollarFromHydration`, reserve matching, and asset transacting disagree about whether the transferred asset is reserve-backed or locally spendable, breaking the invariant that asset backing must remain consistent across local balances, foreign assets, pool assets, reserve-backed assets, and bridged representations, and leading to critical - permanent freeze or loss of bridged or transferred user funds?

## Target
- File/function: `system-parachains/asset-hubs/asset-hub-polkadot/src/xcm_config.rs` :: `PoolAssetsExchanger`
- Entrypoint: `PolkadotXcm::transfer_assets`
- Attacker controls: a location that can be interpreted differently across aliasing, account conversion, and asset transacting code
- Exploit idea: makes `HollarFromHydration`, reserve matching, and asset transacting disagree about whether the transferred asset is reserve-backed or locally spendable
- Invariant to test: asset backing must remain consistent across local balances, foreign assets, pool assets, reserve-backed assets, and bridged representations
- Expected Immunefi impact: Critical - permanent freeze or loss of bridged or transferred user funds
- Fast validation: xcm-emulator test that drives the exact signed or source-chain user path and asserts final origin plus asset balances
