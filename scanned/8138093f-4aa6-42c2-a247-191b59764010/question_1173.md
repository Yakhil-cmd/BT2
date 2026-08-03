# Q1173: alias collision on execution via polkadotxcm transfer assets on Asset Hub Polkadot XCM

## Question
Can an unprivileged attacker enter through `PolkadotXcm::transfer_assets` on Asset Hub Polkadot XCM and control an XCM payload with attacker-chosen origin-shaping instructions, fee asset, beneficiary, and nested `Transact` calls so that `TrustedAliasers` makes `HollarFromHydration`, reserve matching, and asset transacting disagree about whether the transferred asset is reserve-backed or locally spendable, breaking the invariant that the same XCM message must never be treated as both paid and fee-waived for the same execution path, and leading to critical - unauthorized local execution with direct loss of funds?

## Target
- File/function: `system-parachains/asset-hubs/asset-hub-polkadot/src/xcm_config.rs` :: `TrustedAliasers`
- Entrypoint: `PolkadotXcm::transfer_assets`
- Attacker controls: an XCM payload with attacker-chosen origin-shaping instructions, fee asset, beneficiary, and nested `Transact` calls
- Exploit idea: makes `HollarFromHydration`, reserve matching, and asset transacting disagree about whether the transferred asset is reserve-backed or locally spendable
- Invariant to test: the same XCM message must never be treated as both paid and fee-waived for the same execution path
- Expected Immunefi impact: Critical - unauthorized local execution with direct loss of funds
- Fast validation: targeted integration test proving whether the message can reach export, teleport, reserve, or transact paths it should never reach
