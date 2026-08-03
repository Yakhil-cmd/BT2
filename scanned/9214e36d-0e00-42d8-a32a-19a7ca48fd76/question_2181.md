# Q2181: bridge-fee swap drift via assethubpolkadot pallet xcm send on Snowbridge runtime path

## Question
Can an unprivileged attacker enter through `AssetHubPolkadot::pallet_xcm::send` targeting `SnowbridgeFrontendLocation` on Snowbridge runtime path and control bridge payloads that mix local assets, foreign assets, and Ethereum-network locations so that `snowbridge_pallet_system_frontend::Config` makes token-registration authority checks disagree between local-asset and foreign-asset ownership paths, breaking the invariant that bridge registration and settlement must bind one asset identity to one backing asset and one authority model, and leading to critical - direct loss of bridged funds or wrong-asset unlock?

## Target
- File/function: `system-parachains/bridge-hubs/bridge-hub-polkadot/src/bridge_to_ethereum_config.rs` :: `snowbridge_pallet_system_frontend::Config`
- Entrypoint: `AssetHubPolkadot::pallet_xcm::send` targeting `SnowbridgeFrontendLocation`
- Attacker controls: bridge payloads that mix local assets, foreign assets, and Ethereum-network locations
- Exploit idea: makes token-registration authority checks disagree between local-asset and foreign-asset ownership paths
- Invariant to test: bridge registration and settlement must bind one asset identity to one backing asset and one authority model
- Expected Immunefi impact: Critical - direct loss of bridged funds or wrong-asset unlock
- Fast validation: bridge integration test over register-token, send, and settle flows with asset identity assertions
