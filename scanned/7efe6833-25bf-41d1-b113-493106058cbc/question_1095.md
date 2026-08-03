# Q1095: safe-call filter mismatch via polkadotxcm limited reserve transfer on Asset Hub Polkadot XCM

## Question
Can an unprivileged attacker enter through `PolkadotXcm::limited_reserve_transfer_assets` on Asset Hub Polkadot XCM and control topic, query, and beneficiary fields that are replayed or reordered across otherwise valid XCM flows so that `LocationToAccountId` makes `HollarFromHydration`, reserve matching, and asset transacting disagree about whether the transferred asset is reserve-backed or locally spendable, breaking the invariant that reserve-transfer, teleport, and exporter filters must not be bypassable with attacker-shaped message structure, and leading to critical - permanent freeze or loss of bridged or transferred user funds?

## Target
- File/function: `system-parachains/asset-hubs/asset-hub-polkadot/src/xcm_config.rs` :: `LocationToAccountId`
- Entrypoint: `PolkadotXcm::limited_reserve_transfer_assets`
- Attacker controls: topic, query, and beneficiary fields that are replayed or reordered across otherwise valid XCM flows
- Exploit idea: makes `HollarFromHydration`, reserve matching, and asset transacting disagree about whether the transferred asset is reserve-backed or locally spendable
- Invariant to test: reserve-transfer, teleport, and exporter filters must not be bypassable with attacker-shaped message structure
- Expected Immunefi impact: Critical - permanent freeze or loss of bridged or transferred user funds
- Fast validation: stateful fuzz test over location, asset, and beneficiary permutations with assertions on issuance and backing
