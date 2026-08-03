# Q2693: asset-converter split-brain via peoplepolkadot pallet xcm send on People Polkadot XCM

## Question
Can an unprivileged attacker enter through `PeoplePolkadot::pallet_xcm::send` on People Polkadot XCM and control topic, query, and beneficiary fields that are replayed or reordered across otherwise valid XCM flows so that `FeeManager / SendXcmOrigin` makes pre-dispatch fee estimation and final withdrawal disagree on the effective asset, payer, or beneficiary, breaking the invariant that asset backing must remain consistent across local balances, foreign assets, pool assets, reserve-backed assets, and bridged representations, and leading to high - stuck queue or persistent denial of service on a critical transfer path?

## Target
- File/function: `system-parachains/people/people-polkadot/src/xcm_config.rs` :: `FeeManager / SendXcmOrigin`
- Entrypoint: `PeoplePolkadot::pallet_xcm::send`
- Attacker controls: topic, query, and beneficiary fields that are replayed or reordered across otherwise valid XCM flows
- Exploit idea: makes pre-dispatch fee estimation and final withdrawal disagree on the effective asset, payer, or beneficiary
- Invariant to test: asset backing must remain consistent across local balances, foreign assets, pool assets, reserve-backed assets, and bridged representations
- Expected Immunefi impact: High - stuck queue or persistent denial of service on a critical transfer path
- Fast validation: differential test comparing origin/barrier resolution with the final dispatch origin and beneficiary
