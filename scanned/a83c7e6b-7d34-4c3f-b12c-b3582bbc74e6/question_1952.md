# Q1952: alias collision on execution via assethubpolkadot signed user path on Bridge Hub Polkadot XCM

## Question
Can an unprivileged attacker enter through `AssetHubPolkadot signed user path that exports or routes XCM into BridgeHubPolkadot` on Bridge Hub Polkadot XCM and control an export path that can target `XcmOverBridgeHubKusama`, `SnowbridgeExporterV2`, or legacy `SnowbridgeExporter` so that `FeeManager / WaivedLocations` makes the barrier admit execution while the fee or asset path evaluates a different context than dispatch does, breaking the invariant that user-controlled upstream XCM must never acquire the `RelayChainLocation`, `AssetHubLocation`, or `SnowbridgeFrontendLocation` privileges reserved in Bridge Hub, and leading to critical - permanent freeze or loss of bridged or transferred user funds?

## Target
- File/function: `system-parachains/bridge-hubs/bridge-hub-polkadot/src/xcm_config.rs` :: `FeeManager / WaivedLocations`
- Entrypoint: `AssetHubPolkadot signed user path that exports or routes XCM into BridgeHubPolkadot`
- Attacker controls: an export path that can target `XcmOverBridgeHubKusama`, `SnowbridgeExporterV2`, or legacy `SnowbridgeExporter`
- Exploit idea: makes the barrier admit execution while the fee or asset path evaluates a different context than dispatch does
- Invariant to test: user-controlled upstream XCM must never acquire the `RelayChainLocation`, `AssetHubLocation`, or `SnowbridgeFrontendLocation` privileges reserved in Bridge Hub
- Expected Immunefi impact: Critical - permanent freeze or loss of bridged or transferred user funds
- Fast validation: xcm-emulator test that drives the exact signed or source-chain user path and asserts final origin plus asset balances
