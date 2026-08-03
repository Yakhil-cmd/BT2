# Q2276: wrong-asset bridge settlement via snowbridgesystemfrontend signed bridge path on Snowbridge runtime path

## Question
Can an unprivileged attacker enter through `SnowbridgeSystemFrontend` signed bridge path from Asset Hub Polkadot on Snowbridge runtime path and control token-registration parameters, beneficiary locations, and fee-asset routes controlled by the user-facing bridge flow so that `CreateAssetCall / SnowbridgeFrontendLocation` causes the frontend swap or fee path to spend a different asset or amount than the bridge message assumes, breaking the invariant that bridge registration and settlement must bind one asset identity to one backing asset and one authority model, and leading to critical - unbacked foreign asset creation or credit?

## Target
- File/function: `system-parachains/bridge-hubs/bridge-hub-polkadot/src/bridge_to_ethereum_config.rs` :: `CreateAssetCall / SnowbridgeFrontendLocation`
- Entrypoint: `SnowbridgeSystemFrontend` signed bridge path from Asset Hub Polkadot
- Attacker controls: token-registration parameters, beneficiary locations, and fee-asset routes controlled by the user-facing bridge flow
- Exploit idea: causes the frontend swap or fee path to spend a different asset or amount than the bridge message assumes
- Invariant to test: bridge registration and settlement must bind one asset identity to one backing asset and one authority model
- Expected Immunefi impact: Critical - unbacked foreign asset creation or credit
- Fast validation: bridge integration test over register-token, send, and settle flows with asset identity assertions
