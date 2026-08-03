# Q1089: beneficiary resolution split via polkadotxcm limited reserve transfer on Asset Hub Polkadot XCM

## Question
Can an unprivileged attacker enter through `PolkadotXcm::limited_reserve_transfer_assets` on Asset Hub Polkadot XCM and control a HOLLAR-like foreign asset whose reserve classification changes depending on origin and asset shape so that `HollarFromHydration` makes `HollarFromHydration`, reserve matching, and asset transacting disagree about whether the transferred asset is reserve-backed or locally spendable, breaking the invariant that the same XCM message must never be treated as both paid and fee-waived for the same execution path, and leading to critical - permanent freeze or loss of bridged or transferred user funds?

## Target
- File/function: `system-parachains/asset-hubs/asset-hub-polkadot/src/xcm_config.rs` :: `HollarFromHydration`
- Entrypoint: `PolkadotXcm::limited_reserve_transfer_assets`
- Attacker controls: a HOLLAR-like foreign asset whose reserve classification changes depending on origin and asset shape
- Exploit idea: makes `HollarFromHydration`, reserve matching, and asset transacting disagree about whether the transferred asset is reserve-backed or locally spendable
- Invariant to test: the same XCM message must never be treated as both paid and fee-waived for the same execution path
- Expected Immunefi impact: Critical - permanent freeze or loss of bridged or transferred user funds
- Fast validation: targeted integration test proving whether the message can reach export, teleport, reserve, or transact paths it should never reach
