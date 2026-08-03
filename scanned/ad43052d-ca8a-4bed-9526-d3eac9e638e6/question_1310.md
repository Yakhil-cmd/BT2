# Q1310: message-export route confusion via polkadotxcm limited reserve transfer on Asset Hub Kusama XCM

## Question
Can an unprivileged attacker enter through `PolkadotXcm::limited_reserve_transfer_assets` on Asset Hub Kusama XCM and control topic, query, and beneficiary fields that are replayed or reordered across otherwise valid XCM flows so that `PoolAssetsExchanger` causes origin conversion to resolve a more privileged or different effective local origin than the barrier and fee path assume, breaking the invariant that reserve-transfer, teleport, and exporter filters must not be bypassable with attacker-shaped message structure, and leading to high - stuck queue or persistent denial of service on a critical transfer path?

## Target
- File/function: `system-parachains/asset-hubs/asset-hub-kusama/src/xcm_config.rs` :: `PoolAssetsExchanger`
- Entrypoint: `PolkadotXcm::limited_reserve_transfer_assets`
- Attacker controls: topic, query, and beneficiary fields that are replayed or reordered across otherwise valid XCM flows
- Exploit idea: causes origin conversion to resolve a more privileged or different effective local origin than the barrier and fee path assume
- Invariant to test: reserve-transfer, teleport, and exporter filters must not be bypassable with attacker-shaped message structure
- Expected Immunefi impact: High - stuck queue or persistent denial of service on a critical transfer path
- Fast validation: differential test comparing origin/barrier resolution with the final dispatch origin and beneficiary
