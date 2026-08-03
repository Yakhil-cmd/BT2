# Q1828: beneficiary resolution split via assethubpolkadot signed user path on Bridge Hub Polkadot XCM

## Question
Can an unprivileged attacker enter through `AssetHubPolkadot signed user path that exports or routes XCM into BridgeHubPolkadot` on Bridge Hub Polkadot XCM and control topic, query, and beneficiary fields that are replayed or reordered across otherwise valid XCM flows so that `Barrier` makes `DenyExportMessageFrom`, `MessageExporter` ordering, or `LocationAsSuperuser` disagree with the origin and destination the runtime actually uses, breaking the invariant that signed users and user-controlled remote messages must never obtain Root, system-parachain, relay, or privileged plurality execution, and leading to critical - unauthorized local execution with direct loss of funds?

## Target
- File/function: `system-parachains/bridge-hubs/bridge-hub-polkadot/src/xcm_config.rs` :: `Barrier`
- Entrypoint: `AssetHubPolkadot signed user path that exports or routes XCM into BridgeHubPolkadot`
- Attacker controls: topic, query, and beneficiary fields that are replayed or reordered across otherwise valid XCM flows
- Exploit idea: makes `DenyExportMessageFrom`, `MessageExporter` ordering, or `LocationAsSuperuser` disagree with the origin and destination the runtime actually uses
- Invariant to test: signed users and user-controlled remote messages must never obtain Root, system-parachain, relay, or privileged plurality execution
- Expected Immunefi impact: Critical - unauthorized local execution with direct loss of funds
- Fast validation: xcm-emulator test that drives the exact signed or source-chain user path and asserts final origin plus asset balances
