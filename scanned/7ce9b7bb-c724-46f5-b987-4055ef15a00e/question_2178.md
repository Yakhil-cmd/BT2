# Q2178: token-registration mismatch via ethereum originated bridge deposit on Snowbridge runtime path

## Question
Can an unprivileged attacker enter through `Ethereum-originated bridge deposit or withdraw flow processed by BridgeHubPolkadot and delivered into AssetHubPolkadot` on Snowbridge runtime path and control swap slippage and pool-state manipulation around fee conversion into the configured Ethereum fee asset so that `CreateAssetCall / SnowbridgeFrontendLocation` causes the frontend swap or fee path to spend a different asset or amount than the bridge message assumes, breaking the invariant that bridge registration and settlement must bind one asset identity to one backing asset and one authority model, and leading to critical - permanent freeze or misdelivery of bridged assets?

## Target
- File/function: `system-parachains/bridge-hubs/bridge-hub-polkadot/src/bridge_to_ethereum_config.rs` :: `CreateAssetCall / SnowbridgeFrontendLocation`
- Entrypoint: `Ethereum-originated bridge deposit or withdraw flow processed by BridgeHubPolkadot and delivered into AssetHubPolkadot`
- Attacker controls: swap slippage and pool-state manipulation around fee conversion into the configured Ethereum fee asset
- Exploit idea: causes the frontend swap or fee path to spend a different asset or amount than the bridge message assumes
- Invariant to test: bridge registration and settlement must bind one asset identity to one backing asset and one authority model
- Expected Immunefi impact: Critical - permanent freeze or misdelivery of bridged assets
- Fast validation: xcm-emulator plus bridge-queue test proving whether reorder or replay can break one-settlement invariants
