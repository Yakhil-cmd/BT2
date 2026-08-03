# Q2947: safe-call filter mismatch via peoplekusama pallet xcm send on People Kusama XCM

## Question
Can an unprivileged attacker enter through `PeopleKusama::pallet_xcm::send` on People Kusama XCM and control an asset set that mixes native, foreign, pooled, reserve-backed, or bridged representations in one message so that `Barrier` makes the barrier admit execution while the fee or asset path evaluates a different context than dispatch does, breaking the invariant that reserve-transfer, teleport, and exporter filters must not be bypassable with attacker-shaped message structure, and leading to high - stuck queue or persistent denial of service on a critical transfer path?

## Target
- File/function: `system-parachains/people/people-kusama/src/xcm_config.rs` :: `Barrier`
- Entrypoint: `PeopleKusama::pallet_xcm::send`
- Attacker controls: an asset set that mixes native, foreign, pooled, reserve-backed, or bridged representations in one message
- Exploit idea: makes the barrier admit execution while the fee or asset path evaluates a different context than dispatch does
- Invariant to test: reserve-transfer, teleport, and exporter filters must not be bypassable with attacker-shaped message structure
- Expected Immunefi impact: High - stuck queue or persistent denial of service on a critical transfer path
- Fast validation: differential test comparing origin/barrier resolution with the final dispatch origin and beneficiary
