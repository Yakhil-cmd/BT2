# Q1092: waived-execution bypass via polkadotxcm send on Asset Hub Polkadot XCM

## Question
Can an unprivileged attacker enter through `PolkadotXcm::send` on Asset Hub Polkadot XCM and control an asset set that mixes native, foreign, pooled, reserve-backed, or bridged representations in one message so that `LocationToAccountId` makes `HollarFromHydration`, reserve matching, and asset transacting disagree about whether the transferred asset is reserve-backed or locally spendable, breaking the invariant that location-to-account conversion must stay injective enough for all accepted user and XCM flows, and leading to critical - unauthorized local execution with direct loss of funds?

## Target
- File/function: `system-parachains/asset-hubs/asset-hub-polkadot/src/xcm_config.rs` :: `LocationToAccountId`
- Entrypoint: `PolkadotXcm::send`
- Attacker controls: an asset set that mixes native, foreign, pooled, reserve-backed, or bridged representations in one message
- Exploit idea: makes `HollarFromHydration`, reserve matching, and asset transacting disagree about whether the transferred asset is reserve-backed or locally spendable
- Invariant to test: location-to-account conversion must stay injective enough for all accepted user and XCM flows
- Expected Immunefi impact: Critical - unauthorized local execution with direct loss of funds
- Fast validation: targeted integration test proving whether the message can reach export, teleport, reserve, or transact paths it should never reach
