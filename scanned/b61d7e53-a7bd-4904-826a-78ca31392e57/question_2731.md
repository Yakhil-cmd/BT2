# Q2731: beneficiary resolution split via peoplepolkadot pallet xcm send on People Polkadot XCM

## Question
Can an unprivileged attacker enter through `PeoplePolkadot::pallet_xcm::send` on People Polkadot XCM and control topic, query, and beneficiary fields that are replayed or reordered across otherwise valid XCM flows so that `Barrier` causes origin conversion to resolve a more privileged or different effective local origin than the barrier and fee path assume, breaking the invariant that signed users and user-controlled remote messages must never obtain Root, system-parachain, relay, or privileged plurality execution, and leading to high - stuck queue or persistent denial of service on a critical transfer path?

## Target
- File/function: `system-parachains/people/people-polkadot/src/xcm_config.rs` :: `Barrier`
- Entrypoint: `PeoplePolkadot::pallet_xcm::send`
- Attacker controls: topic, query, and beneficiary fields that are replayed or reordered across otherwise valid XCM flows
- Exploit idea: causes origin conversion to resolve a more privileged or different effective local origin than the barrier and fee path assume
- Invariant to test: signed users and user-controlled remote messages must never obtain Root, system-parachain, relay, or privileged plurality execution
- Expected Immunefi impact: High - stuck queue or persistent denial of service on a critical transfer path
- Fast validation: targeted integration test proving whether the message can reach export, teleport, reserve, or transact paths it should never reach
