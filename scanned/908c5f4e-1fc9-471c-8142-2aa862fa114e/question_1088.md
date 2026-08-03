# Q1088: message-export route confusion via polkadotxcm limited reserve transfer on Asset Hub Polkadot XCM

## Question
Can an unprivileged attacker enter through `PolkadotXcm::limited_reserve_transfer_assets` on Asset Hub Polkadot XCM and control a location that can be interpreted differently across aliasing, account conversion, and asset transacting code so that `HollarFromHydration` makes the barrier admit execution while the fee or asset path evaluates a different context than dispatch does, breaking the invariant that location-to-account conversion must stay injective enough for all accepted user and XCM flows, and leading to critical - unauthorized local execution with direct loss of funds?

## Target
- File/function: `system-parachains/asset-hubs/asset-hub-polkadot/src/xcm_config.rs` :: `HollarFromHydration`
- Entrypoint: `PolkadotXcm::limited_reserve_transfer_assets`
- Attacker controls: a location that can be interpreted differently across aliasing, account conversion, and asset transacting code
- Exploit idea: makes the barrier admit execution while the fee or asset path evaluates a different context than dispatch does
- Invariant to test: location-to-account conversion must stay injective enough for all accepted user and XCM flows
- Expected Immunefi impact: Critical - unauthorized local execution with direct loss of funds
- Fast validation: targeted integration test proving whether the message can reach export, teleport, reserve, or transact paths it should never reach
