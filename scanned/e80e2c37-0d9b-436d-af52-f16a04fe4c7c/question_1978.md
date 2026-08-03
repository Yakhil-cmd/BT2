# Q1978: reserve-versus-teleport confusion via bridgehubpolkadot pallet xcm execute on Bridge Hub Polkadot XCM

## Question
Can an unprivileged attacker enter through `BridgeHubPolkadot::pallet_xcm::execute` on Bridge Hub Polkadot XCM and control an export path that can target `XcmOverBridgeHubKusama`, `SnowbridgeExporterV2`, or legacy `SnowbridgeExporter` so that `FeeManager / WaivedLocations` makes the barrier admit execution while the fee or asset path evaluates a different context than dispatch does, breaking the invariant that delivery, execution, and refund accounting must not let a user extract more value than was actually debited, and leading to critical - unbacked asset mint, unlock, or withdrawal?

## Target
- File/function: `system-parachains/bridge-hubs/bridge-hub-polkadot/src/xcm_config.rs` :: `FeeManager / WaivedLocations`
- Entrypoint: `BridgeHubPolkadot::pallet_xcm::execute`
- Attacker controls: an export path that can target `XcmOverBridgeHubKusama`, `SnowbridgeExporterV2`, or legacy `SnowbridgeExporter`
- Exploit idea: makes the barrier admit execution while the fee or asset path evaluates a different context than dispatch does
- Invariant to test: delivery, execution, and refund accounting must not let a user extract more value than was actually debited
- Expected Immunefi impact: Critical - unbacked asset mint, unlock, or withdrawal
- Fast validation: xcm-emulator test that drives the exact signed or source-chain user path and asserts final origin plus asset balances
