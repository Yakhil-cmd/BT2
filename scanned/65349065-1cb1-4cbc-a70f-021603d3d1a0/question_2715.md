# Q2715: safe-call filter mismatch via peoplepolkadot pallet xcm send on People Polkadot XCM

## Question
Can an unprivileged attacker enter through `PeoplePolkadot::pallet_xcm::send` on People Polkadot XCM and control topic, query, and beneficiary fields that are replayed or reordered across otherwise valid XCM flows so that `Barrier` makes the barrier admit execution while the fee or asset path evaluates a different context than dispatch does, breaking the invariant that delivery, execution, and refund accounting must not let a user extract more value than was actually debited, and leading to high - stuck queue or persistent denial of service on a critical transfer path?

## Target
- File/function: `system-parachains/people/people-polkadot/src/xcm_config.rs` :: `Barrier`
- Entrypoint: `PeoplePolkadot::pallet_xcm::send`
- Attacker controls: topic, query, and beneficiary fields that are replayed or reordered across otherwise valid XCM flows
- Exploit idea: makes the barrier admit execution while the fee or asset path evaluates a different context than dispatch does
- Invariant to test: delivery, execution, and refund accounting must not let a user extract more value than was actually debited
- Expected Immunefi impact: High - stuck queue or persistent denial of service on a critical transfer path
- Fast validation: differential test comparing origin/barrier resolution with the final dispatch origin and beneficiary
