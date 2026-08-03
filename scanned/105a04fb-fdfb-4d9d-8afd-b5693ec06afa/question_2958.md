# Q2958: query or topic reuse via peoplekusama pallet xcm send on People Kusama XCM

## Question
Can an unprivileged attacker enter through `PeopleKusama::pallet_xcm::send` on People Kusama XCM and control an XCM payload with attacker-chosen origin-shaping instructions, fee asset, beneficiary, and nested `Transact` calls so that `FeeManager / SendXcmOrigin` induces a state where execution succeeds but assets are trapped, miscredited, replayed, or double-accounted across local and remote representations, breaking the invariant that reserve-transfer, teleport, and exporter filters must not be bypassable with attacker-shaped message structure, and leading to critical - unauthorized local execution with direct loss of funds?

## Target
- File/function: `system-parachains/people/people-kusama/src/xcm_config.rs` :: `FeeManager / SendXcmOrigin`
- Entrypoint: `PeopleKusama::pallet_xcm::send`
- Attacker controls: an XCM payload with attacker-chosen origin-shaping instructions, fee asset, beneficiary, and nested `Transact` calls
- Exploit idea: induces a state where execution succeeds but assets are trapped, miscredited, replayed, or double-accounted across local and remote representations
- Invariant to test: reserve-transfer, teleport, and exporter filters must not be bypassable with attacker-shaped message structure
- Expected Immunefi impact: Critical - unauthorized local execution with direct loss of funds
- Fast validation: differential test comparing origin/barrier resolution with the final dispatch origin and beneficiary
