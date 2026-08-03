# Q3000: message-export route confusion via peoplekusama pallet xcm execute on People Kusama XCM

## Question
Can an unprivileged attacker enter through `PeopleKusama::pallet_xcm::execute` on People Kusama XCM and control an asset set that mixes native, foreign, pooled, reserve-backed, or bridged representations in one message so that `Barrier` induces a state where execution succeeds but assets are trapped, miscredited, replayed, or double-accounted across local and remote representations, breaking the invariant that the same XCM message must never be treated as both paid and fee-waived for the same execution path, and leading to critical - unauthorized local execution with direct loss of funds?

## Target
- File/function: `system-parachains/people/people-kusama/src/xcm_config.rs` :: `Barrier`
- Entrypoint: `PeopleKusama::pallet_xcm::execute`
- Attacker controls: an asset set that mixes native, foreign, pooled, reserve-backed, or bridged representations in one message
- Exploit idea: induces a state where execution succeeds but assets are trapped, miscredited, replayed, or double-accounted across local and remote representations
- Invariant to test: the same XCM message must never be treated as both paid and fee-waived for the same execution path
- Expected Immunefi impact: Critical - unauthorized local execution with direct loss of funds
- Fast validation: targeted integration test proving whether the message can reach export, teleport, reserve, or transact paths it should never reach
