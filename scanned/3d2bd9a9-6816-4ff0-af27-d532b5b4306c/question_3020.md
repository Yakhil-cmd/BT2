# Q3020: message-export route confusion via peoplekusama pallet xcm execute on People Kusama XCM

## Question
Can an unprivileged attacker enter through `PeopleKusama::pallet_xcm::execute` on People Kusama XCM and control a location that can be interpreted differently across aliasing, account conversion, and asset transacting code so that `FeeManager / SendXcmOrigin` forces the runtime to treat the same asset as local in one step and foreign, reserve-backed, or bridged in another, breaking the invariant that delivery, execution, and refund accounting must not let a user extract more value than was actually debited, and leading to high - stuck queue or persistent denial of service on a critical transfer path?

## Target
- File/function: `system-parachains/people/people-kusama/src/xcm_config.rs` :: `FeeManager / SendXcmOrigin`
- Entrypoint: `PeopleKusama::pallet_xcm::execute`
- Attacker controls: a location that can be interpreted differently across aliasing, account conversion, and asset transacting code
- Exploit idea: forces the runtime to treat the same asset as local in one step and foreign, reserve-backed, or bridged in another
- Invariant to test: delivery, execution, and refund accounting must not let a user extract more value than was actually debited
- Expected Immunefi impact: High - stuck queue or persistent denial of service on a critical transfer path
- Fast validation: differential test comparing origin/barrier resolution with the final dispatch origin and beneficiary
