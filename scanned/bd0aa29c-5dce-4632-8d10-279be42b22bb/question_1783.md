# Q1783: Snowbridge export bypass via signed user flow whose on Bridge Hub Polkadot XCM

## Question
Can an unprivileged attacker enter through `signed user flow whose message enters BridgeHubPolkadot through a valid upstream XCM route` on Bridge Hub Polkadot XCM and control an asset set that mixes native, foreign, pooled, reserve-backed, or bridged representations in one message so that `MessageExporter` makes `DenyExportMessageFrom`, `MessageExporter` ordering, or `LocationAsSuperuser` disagree with the origin and destination the runtime actually uses, breaking the invariant that reserve-transfer, teleport, and exporter filters must not be bypassable with attacker-shaped message structure, and leading to critical - unauthorized local execution with direct loss of funds?

## Target
- File/function: `system-parachains/bridge-hubs/bridge-hub-polkadot/src/xcm_config.rs` :: `MessageExporter`
- Entrypoint: `signed user flow whose message enters BridgeHubPolkadot through a valid upstream XCM route`
- Attacker controls: an asset set that mixes native, foreign, pooled, reserve-backed, or bridged representations in one message
- Exploit idea: makes `DenyExportMessageFrom`, `MessageExporter` ordering, or `LocationAsSuperuser` disagree with the origin and destination the runtime actually uses
- Invariant to test: reserve-transfer, teleport, and exporter filters must not be bypassable with attacker-shaped message structure
- Expected Immunefi impact: Critical - unauthorized local execution with direct loss of funds
- Fast validation: xcm-emulator test that drives the exact signed or source-chain user path and asserts final origin plus asset balances
