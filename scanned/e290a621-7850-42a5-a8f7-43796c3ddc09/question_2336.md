# Q2336: wrong-asset bridge settlement via assethubpolkadot pallet xcm send on Snowbridge runtime path

## Question
Can an unprivileged attacker enter through `AssetHubPolkadot::pallet_xcm::send` targeting `SnowbridgeFrontendLocation` on Snowbridge runtime path and control repeated or reordered bridge messages that race token registration, reserve assignment, and asset creation so that `CreateAssetCall / SnowbridgeFrontendLocation` causes the frontend swap or fee path to spend a different asset or amount than the bridge message assumes, breaking the invariant that inbound and outbound bridge processing must not double-create, double-credit, or misroute foreign assets, and leading to critical - direct loss of bridged funds or wrong-asset unlock?

## Target
- File/function: `system-parachains/bridge-hubs/bridge-hub-polkadot/src/bridge_to_ethereum_config.rs` :: `CreateAssetCall / SnowbridgeFrontendLocation`
- Entrypoint: `AssetHubPolkadot::pallet_xcm::send` targeting `SnowbridgeFrontendLocation`
- Attacker controls: repeated or reordered bridge messages that race token registration, reserve assignment, and asset creation
- Exploit idea: causes the frontend swap or fee path to spend a different asset or amount than the bridge message assumes
- Invariant to test: inbound and outbound bridge processing must not double-create, double-credit, or misroute foreign assets
- Expected Immunefi impact: Critical - direct loss of bridged funds or wrong-asset unlock
- Fast validation: bridge integration test over register-token, send, and settle flows with asset identity assertions
