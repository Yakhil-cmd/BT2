# Q2302: token-registration mismatch via snowbridgesystemfrontend signed bridge path on Snowbridge runtime path

## Question
Can an unprivileged attacker enter through `SnowbridgeSystemFrontend` signed bridge path from Asset Hub Polkadot on Snowbridge runtime path and control token-registration parameters, beneficiary locations, and fee-asset routes controlled by the user-facing bridge flow so that `SnowbridgeExporter / SnowbridgeExporterV2` makes token-registration authority checks disagree between local-asset and foreign-asset ownership paths, breaking the invariant that front-end fee conversion must not let a user spend less than the bridge path credits or unlocks, and leading to critical - permanent freeze or misdelivery of bridged assets?

## Target
- File/function: `system-parachains/bridge-hubs/bridge-hub-polkadot/src/bridge_to_ethereum_config.rs` :: `SnowbridgeExporter / SnowbridgeExporterV2`
- Entrypoint: `SnowbridgeSystemFrontend` signed bridge path from Asset Hub Polkadot
- Attacker controls: token-registration parameters, beneficiary locations, and fee-asset routes controlled by the user-facing bridge flow
- Exploit idea: makes token-registration authority checks disagree between local-asset and foreign-asset ownership paths
- Invariant to test: front-end fee conversion must not let a user spend less than the bridge path credits or unlocks
- Expected Immunefi impact: Critical - permanent freeze or misdelivery of bridged assets
- Fast validation: bridge integration test over register-token, send, and settle flows with asset identity assertions
