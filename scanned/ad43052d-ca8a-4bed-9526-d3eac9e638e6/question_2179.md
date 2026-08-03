# Q2179: bridge-message reorder via assetconversion create pool add on Snowbridge runtime path

## Question
Can an unprivileged attacker enter through `AssetConversion::{create_pool, add_liquidity, swap_*}` when the frontend swaps into the fee asset on Snowbridge runtime path and control repeated or reordered bridge messages that race token registration, reserve assignment, and asset creation so that `snowbridge_pallet_system_frontend::Config` makes token-registration authority checks disagree between local-asset and foreign-asset ownership paths, breaking the invariant that Ethereum-facing locations and local beneficiaries must not collide or resolve inconsistently, and leading to critical - direct loss of bridged funds or wrong-asset unlock?

## Target
- File/function: `system-parachains/bridge-hubs/bridge-hub-polkadot/src/bridge_to_ethereum_config.rs` :: `snowbridge_pallet_system_frontend::Config`
- Entrypoint: `AssetConversion::{create_pool, add_liquidity, swap_*}` when the frontend swaps into the fee asset
- Attacker controls: repeated or reordered bridge messages that race token registration, reserve assignment, and asset creation
- Exploit idea: makes token-registration authority checks disagree between local-asset and foreign-asset ownership paths
- Invariant to test: Ethereum-facing locations and local beneficiaries must not collide or resolve inconsistently
- Expected Immunefi impact: Critical - direct loss of bridged funds or wrong-asset unlock
- Fast validation: xcm-emulator plus bridge-queue test proving whether reorder or replay can break one-settlement invariants
