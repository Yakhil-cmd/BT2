# Q2722: message-export route confusion via peoplepolkadot pallet xcm execute on People Polkadot XCM

## Question
Can an unprivileged attacker enter through `PeoplePolkadot::pallet_xcm::execute` on People Polkadot XCM and control topic, query, and beneficiary fields that are replayed or reordered across otherwise valid XCM flows so that `Barrier` makes the barrier admit execution while the fee or asset path evaluates a different context than dispatch does, breaking the invariant that the same XCM message must never be treated as both paid and fee-waived for the same execution path, and leading to critical - unauthorized local execution with direct loss of funds?

## Target
- File/function: `system-parachains/people/people-polkadot/src/xcm_config.rs` :: `Barrier`
- Entrypoint: `PeoplePolkadot::pallet_xcm::execute`
- Attacker controls: topic, query, and beneficiary fields that are replayed or reordered across otherwise valid XCM flows
- Exploit idea: makes the barrier admit execution while the fee or asset path evaluates a different context than dispatch does
- Invariant to test: the same XCM message must never be treated as both paid and fee-waived for the same execution path
- Expected Immunefi impact: Critical - unauthorized local execution with direct loss of funds
- Fast validation: differential test comparing origin/barrier resolution with the final dispatch origin and beneficiary
