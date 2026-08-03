# Q1131: reserve-versus-teleport confusion via polkadotxcm limited reserve transfer on Asset Hub Polkadot XCM

## Question
Can an unprivileged attacker enter through `PolkadotXcm::limited_reserve_transfer_assets` on Asset Hub Polkadot XCM and control an XCM payload with attacker-chosen origin-shaping instructions, fee asset, beneficiary, and nested `Transact` calls so that `FeeManager` forces the runtime to treat the same asset as local in one step and foreign, reserve-backed, or bridged in another, breaking the invariant that reserve-transfer, teleport, and exporter filters must not be bypassable with attacker-shaped message structure, and leading to critical - unbacked asset mint, unlock, or withdrawal?

## Target
- File/function: `system-parachains/asset-hubs/asset-hub-polkadot/src/xcm_config.rs` :: `FeeManager`
- Entrypoint: `PolkadotXcm::limited_reserve_transfer_assets`
- Attacker controls: an XCM payload with attacker-chosen origin-shaping instructions, fee asset, beneficiary, and nested `Transact` calls
- Exploit idea: forces the runtime to treat the same asset as local in one step and foreign, reserve-backed, or bridged in another
- Invariant to test: reserve-transfer, teleport, and exporter filters must not be bypassable with attacker-shaped message structure
- Expected Immunefi impact: Critical - unbacked asset mint, unlock, or withdrawal
- Fast validation: targeted integration test proving whether the message can reach export, teleport, reserve, or transact paths it should never reach
