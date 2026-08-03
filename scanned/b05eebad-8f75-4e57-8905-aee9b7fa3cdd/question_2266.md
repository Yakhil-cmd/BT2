# Q2266: token-registration mismatch via ethereum originated bridge deposit on Snowbridge runtime path

## Question
Can an unprivileged attacker enter through `Ethereum-originated bridge deposit or withdraw flow processed by BridgeHubPolkadot and delivered into AssetHubPolkadot` on Snowbridge runtime path and control repeated or reordered bridge messages that race token registration, reserve assignment, and asset creation so that `SnowbridgeExporter / SnowbridgeExporterV2` makes token-registration authority checks disagree between local-asset and foreign-asset ownership paths, breaking the invariant that bridge registration and settlement must bind one asset identity to one backing asset and one authority model, and leading to critical - permanent freeze or misdelivery of bridged assets?

## Target
- File/function: `system-parachains/bridge-hubs/bridge-hub-polkadot/src/bridge_to_ethereum_config.rs` :: `SnowbridgeExporter / SnowbridgeExporterV2`
- Entrypoint: `Ethereum-originated bridge deposit or withdraw flow processed by BridgeHubPolkadot and delivered into AssetHubPolkadot`
- Attacker controls: repeated or reordered bridge messages that race token registration, reserve assignment, and asset creation
- Exploit idea: makes token-registration authority checks disagree between local-asset and foreign-asset ownership paths
- Invariant to test: bridge registration and settlement must bind one asset identity to one backing asset and one authority model
- Expected Immunefi impact: Critical - permanent freeze or misdelivery of bridged assets
- Fast validation: bridge integration test over register-token, send, and settle flows with asset identity assertions
