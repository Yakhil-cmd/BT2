# Q1087: asset-converter split-brain via polkadotxcm transfer assets on Asset Hub Polkadot XCM

## Question
Can an unprivileged attacker enter through `PolkadotXcm::transfer_assets` on Asset Hub Polkadot XCM and control an asset set that mixes native, foreign, pooled, reserve-backed, or bridged representations in one message so that `HollarFromHydration` reaches an exporter, alias, teleporter, or reserve path that should only be reachable from a tighter origin class, breaking the invariant that reserve-transfer, teleport, and exporter filters must not be bypassable with attacker-shaped message structure, and leading to critical - permanent freeze or loss of bridged or transferred user funds?

## Target
- File/function: `system-parachains/asset-hubs/asset-hub-polkadot/src/xcm_config.rs` :: `HollarFromHydration`
- Entrypoint: `PolkadotXcm::transfer_assets`
- Attacker controls: an asset set that mixes native, foreign, pooled, reserve-backed, or bridged representations in one message
- Exploit idea: reaches an exporter, alias, teleporter, or reserve path that should only be reachable from a tighter origin class
- Invariant to test: reserve-transfer, teleport, and exporter filters must not be bypassable with attacker-shaped message structure
- Expected Immunefi impact: Critical - permanent freeze or loss of bridged or transferred user funds
- Fast validation: targeted integration test proving whether the message can reach export, teleport, reserve, or transact paths it should never reach
