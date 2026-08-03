# Q1855: waived-execution bypass via assethubpolkadot signed user path on Bridge Hub Polkadot XCM

## Question
Can an unprivileged attacker enter through `AssetHubPolkadot signed user path that exports or routes XCM into BridgeHubPolkadot` on Bridge Hub Polkadot XCM and control an execution path that alternates between paid execution, explicitly unpaid execution, and refund handling so that `Barrier` forces the runtime to treat the same asset as local in one step and foreign, reserve-backed, or bridged in another, breaking the invariant that user-controlled upstream XCM must never acquire the `RelayChainLocation`, `AssetHubLocation`, or `SnowbridgeFrontendLocation` privileges reserved in Bridge Hub, and leading to critical - unauthorized local execution with direct loss of funds?

## Target
- File/function: `system-parachains/bridge-hubs/bridge-hub-polkadot/src/xcm_config.rs` :: `Barrier`
- Entrypoint: `AssetHubPolkadot signed user path that exports or routes XCM into BridgeHubPolkadot`
- Attacker controls: an execution path that alternates between paid execution, explicitly unpaid execution, and refund handling
- Exploit idea: forces the runtime to treat the same asset as local in one step and foreign, reserve-backed, or bridged in another
- Invariant to test: user-controlled upstream XCM must never acquire the `RelayChainLocation`, `AssetHubLocation`, or `SnowbridgeFrontendLocation` privileges reserved in Bridge Hub
- Expected Immunefi impact: Critical - unauthorized local execution with direct loss of funds
- Fast validation: xcm-emulator test that drives the exact signed or source-chain user path and asserts final origin plus asset balances
