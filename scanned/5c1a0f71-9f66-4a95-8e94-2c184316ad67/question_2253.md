# Q2253: bridge-fee swap drift via assethubpolkadot pallet xcm send on Snowbridge runtime path

## Question
Can an unprivileged attacker enter through `AssetHubPolkadot::pallet_xcm::send` targeting `SnowbridgeFrontendLocation` on Snowbridge runtime path and control repeated or reordered bridge messages that race token registration, reserve assignment, and asset creation so that `SnowbridgeExporter / SnowbridgeExporterV2` makes token-registration authority checks disagree between local-asset and foreign-asset ownership paths, breaking the invariant that inbound and outbound bridge processing must not double-create, double-credit, or misroute foreign assets, and leading to critical - direct loss of bridged funds or wrong-asset unlock?

## Target
- File/function: `system-parachains/bridge-hubs/bridge-hub-polkadot/src/bridge_to_ethereum_config.rs` :: `SnowbridgeExporter / SnowbridgeExporterV2`
- Entrypoint: `AssetHubPolkadot::pallet_xcm::send` targeting `SnowbridgeFrontendLocation`
- Attacker controls: repeated or reordered bridge messages that race token registration, reserve assignment, and asset creation
- Exploit idea: makes token-registration authority checks disagree between local-asset and foreign-asset ownership paths
- Invariant to test: inbound and outbound bridge processing must not double-create, double-credit, or misroute foreign assets
- Expected Immunefi impact: Critical - direct loss of bridged funds or wrong-asset unlock
- Fast validation: bridge integration test over register-token, send, and settle flows with asset identity assertions
