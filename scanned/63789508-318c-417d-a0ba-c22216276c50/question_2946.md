# Q2946: origin-conversion mismatch via peoplekusama pallet xcm execute on People Kusama XCM

## Question
Can an unprivileged attacker enter through `PeopleKusama::pallet_xcm::execute` on People Kusama XCM and control an asset set that mixes native, foreign, pooled, reserve-backed, or bridged representations in one message so that `Barrier` induces a state where execution succeeds but assets are trapped, miscredited, replayed, or double-accounted across local and remote representations, breaking the invariant that reserve-transfer, teleport, and exporter filters must not be bypassable with attacker-shaped message structure, and leading to high - stuck queue or persistent denial of service on a critical transfer path?

## Target
- File/function: `system-parachains/people/people-kusama/src/xcm_config.rs` :: `Barrier`
- Entrypoint: `PeopleKusama::pallet_xcm::execute`
- Attacker controls: an asset set that mixes native, foreign, pooled, reserve-backed, or bridged representations in one message
- Exploit idea: induces a state where execution succeeds but assets are trapped, miscredited, replayed, or double-accounted across local and remote representations
- Invariant to test: reserve-transfer, teleport, and exporter filters must not be bypassable with attacker-shaped message structure
- Expected Immunefi impact: High - stuck queue or persistent denial of service on a critical transfer path
- Fast validation: targeted integration test proving whether the message can reach export, teleport, reserve, or transact paths it should never reach
