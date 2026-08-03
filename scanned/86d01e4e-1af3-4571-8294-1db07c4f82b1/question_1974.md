# Q1974: alias collision on execution via assethubpolkadot signed user path on Bridge Hub Polkadot XCM

## Question
Can an unprivileged attacker enter through `AssetHubPolkadot signed user path that exports or routes XCM into BridgeHubPolkadot` on Bridge Hub Polkadot XCM and control a location that can be interpreted differently across aliasing, account conversion, and asset transacting code so that `MessageExporter` makes `DenyExportMessageFrom`, `MessageExporter` ordering, or `LocationAsSuperuser` disagree with the origin and destination the runtime actually uses, breaking the invariant that reserve-transfer, teleport, and exporter filters must not be bypassable with attacker-shaped message structure, and leading to critical - unbacked asset mint, unlock, or withdrawal?

## Target
- File/function: `system-parachains/bridge-hubs/bridge-hub-polkadot/src/xcm_config.rs` :: `MessageExporter`
- Entrypoint: `AssetHubPolkadot signed user path that exports or routes XCM into BridgeHubPolkadot`
- Attacker controls: a location that can be interpreted differently across aliasing, account conversion, and asset transacting code
- Exploit idea: makes `DenyExportMessageFrom`, `MessageExporter` ordering, or `LocationAsSuperuser` disagree with the origin and destination the runtime actually uses
- Invariant to test: reserve-transfer, teleport, and exporter filters must not be bypassable with attacker-shaped message structure
- Expected Immunefi impact: Critical - unbacked asset mint, unlock, or withdrawal
- Fast validation: stateful fuzz test over location, asset, and beneficiary permutations with assertions on issuance and backing
