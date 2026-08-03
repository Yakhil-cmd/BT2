# Q2201: bridge-fee swap drift via assethubpolkadot pallet xcm send on Snowbridge runtime path

## Question
Can an unprivileged attacker enter through `AssetHubPolkadot::pallet_xcm::send` targeting `SnowbridgeFrontendLocation` on Snowbridge runtime path and control repeated or reordered bridge messages that race token registration, reserve assignment, and asset creation so that `snowbridge_pallet_inbound_queue_v2::Config` causes the frontend swap or fee path to spend a different asset or amount than the bridge message assumes, breaking the invariant that Ethereum-facing locations and local beneficiaries must not collide or resolve inconsistently, and leading to critical - direct loss of bridged funds or wrong-asset unlock?

## Target
- File/function: `system-parachains/bridge-hubs/bridge-hub-polkadot/src/bridge_to_ethereum_config.rs` :: `snowbridge_pallet_inbound_queue_v2::Config`
- Entrypoint: `AssetHubPolkadot::pallet_xcm::send` targeting `SnowbridgeFrontendLocation`
- Attacker controls: repeated or reordered bridge messages that race token registration, reserve assignment, and asset creation
- Exploit idea: causes the frontend swap or fee path to spend a different asset or amount than the bridge message assumes
- Invariant to test: Ethereum-facing locations and local beneficiaries must not collide or resolve inconsistently
- Expected Immunefi impact: Critical - direct loss of bridged funds or wrong-asset unlock
- Fast validation: xcm-emulator plus bridge-queue test proving whether reorder or replay can break one-settlement invariants
