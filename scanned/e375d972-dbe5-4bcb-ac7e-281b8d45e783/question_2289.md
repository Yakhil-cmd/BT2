# Q2289: bridge-fee swap drift via assetconversion create pool add on Snowbridge runtime path

## Question
Can an unprivileged attacker enter through `AssetConversion::{create_pool, add_liquidity, swap_*}` when the frontend swaps into the fee asset on Snowbridge runtime path and control token-registration parameters, beneficiary locations, and fee-asset routes controlled by the user-facing bridge flow so that `CreateAssetCall / SnowbridgeFrontendLocation` makes token-registration authority checks disagree between local-asset and foreign-asset ownership paths, breaking the invariant that Ethereum-facing locations and local beneficiaries must not collide or resolve inconsistently, and leading to critical - direct loss of bridged funds or wrong-asset unlock?

## Target
- File/function: `system-parachains/bridge-hubs/bridge-hub-polkadot/src/bridge_to_ethereum_config.rs` :: `CreateAssetCall / SnowbridgeFrontendLocation`
- Entrypoint: `AssetConversion::{create_pool, add_liquidity, swap_*}` when the frontend swaps into the fee asset
- Attacker controls: token-registration parameters, beneficiary locations, and fee-asset routes controlled by the user-facing bridge flow
- Exploit idea: makes token-registration authority checks disagree between local-asset and foreign-asset ownership paths
- Invariant to test: Ethereum-facing locations and local beneficiaries must not collide or resolve inconsistently
- Expected Immunefi impact: Critical - direct loss of bridged funds or wrong-asset unlock
- Fast validation: bridge integration test over register-token, send, and settle flows with asset identity assertions
