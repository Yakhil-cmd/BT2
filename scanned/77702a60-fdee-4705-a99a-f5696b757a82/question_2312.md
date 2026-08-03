# Q2312: wrong-asset bridge settlement via snowbridgesystemfrontend signed bridge path on Snowbridge runtime path

## Question
Can an unprivileged attacker enter through `SnowbridgeSystemFrontend` signed bridge path from Asset Hub Polkadot on Snowbridge runtime path and control bridge payloads that mix local assets, foreign assets, and Ethereum-network locations so that `snowbridge_pallet_inbound_queue_v2::Config` causes the frontend swap or fee path to spend a different asset or amount than the bridge message assumes, breaking the invariant that front-end fee conversion must not let a user spend less than the bridge path credits or unlocks, and leading to critical - unbacked foreign asset creation or credit?

## Target
- File/function: `system-parachains/bridge-hubs/bridge-hub-polkadot/src/bridge_to_ethereum_config.rs` :: `snowbridge_pallet_inbound_queue_v2::Config`
- Entrypoint: `SnowbridgeSystemFrontend` signed bridge path from Asset Hub Polkadot
- Attacker controls: bridge payloads that mix local assets, foreign assets, and Ethereum-network locations
- Exploit idea: causes the frontend swap or fee path to spend a different asset or amount than the bridge message assumes
- Invariant to test: front-end fee conversion must not let a user spend less than the bridge path credits or unlocks
- Expected Immunefi impact: Critical - unbacked foreign asset creation or credit
- Fast validation: bridge integration test over register-token, send, and settle flows with asset identity assertions
