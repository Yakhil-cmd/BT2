# Q1295: alias collision on execution via polkadotxcm limited reserve transfer on Asset Hub Kusama XCM

## Question
Can an unprivileged attacker enter through `PolkadotXcm::limited_reserve_transfer_assets` on Asset Hub Kusama XCM and control topic, query, and beneficiary fields that are replayed or reordered across otherwise valid XCM flows so that `FeeManager` reaches an exporter, alias, teleporter, or reserve path that should only be reachable from a tighter origin class, breaking the invariant that signed users and user-controlled remote messages must never obtain Root, system-parachain, relay, or privileged plurality execution, and leading to critical - unbacked asset mint, unlock, or withdrawal?

## Target
- File/function: `system-parachains/asset-hubs/asset-hub-kusama/src/xcm_config.rs` :: `FeeManager`
- Entrypoint: `PolkadotXcm::limited_reserve_transfer_assets`
- Attacker controls: topic, query, and beneficiary fields that are replayed or reordered across otherwise valid XCM flows
- Exploit idea: reaches an exporter, alias, teleporter, or reserve path that should only be reachable from a tighter origin class
- Invariant to test: signed users and user-controlled remote messages must never obtain Root, system-parachain, relay, or privileged plurality execution
- Expected Immunefi impact: Critical - unbacked asset mint, unlock, or withdrawal
- Fast validation: xcm-emulator test that drives the exact signed or source-chain user path and asserts final origin plus asset balances
