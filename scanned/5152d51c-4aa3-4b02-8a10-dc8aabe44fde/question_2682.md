# Q2682: message-export route confusion via peoplepolkadot pallet xcm execute on People Polkadot XCM

## Question
Can an unprivileged attacker enter through `PeoplePolkadot::pallet_xcm::execute` on People Polkadot XCM and control topic, query, and beneficiary fields that are replayed or reordered across otherwise valid XCM flows so that `Barrier` induces a state where execution succeeds but assets are trapped, miscredited, replayed, or double-accounted across local and remote representations, breaking the invariant that reserve-transfer, teleport, and exporter filters must not be bypassable with attacker-shaped message structure, and leading to critical - unbacked asset mint, unlock, or withdrawal?

## Target
- File/function: `system-parachains/people/people-polkadot/src/xcm_config.rs` :: `Barrier`
- Entrypoint: `PeoplePolkadot::pallet_xcm::execute`
- Attacker controls: topic, query, and beneficiary fields that are replayed or reordered across otherwise valid XCM flows
- Exploit idea: induces a state where execution succeeds but assets are trapped, miscredited, replayed, or double-accounted across local and remote representations
- Invariant to test: reserve-transfer, teleport, and exporter filters must not be bypassable with attacker-shaped message structure
- Expected Immunefi impact: Critical - unbacked asset mint, unlock, or withdrawal
- Fast validation: differential test comparing origin/barrier resolution with the final dispatch origin and beneficiary
