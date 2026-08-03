# Q2710: fee-asset undercharge path via peoplepolkadot pallet xcm execute on People Polkadot XCM

## Question
Can an unprivileged attacker enter through `PeoplePolkadot::pallet_xcm::execute` on People Polkadot XCM and control topic, query, and beneficiary fields that are replayed or reordered across otherwise valid XCM flows so that `LocationToAccountId` forces the runtime to treat the same asset as local in one step and foreign, reserve-backed, or bridged in another, breaking the invariant that location-to-account conversion must stay injective enough for all accepted user and XCM flows, and leading to critical - unbacked asset mint, unlock, or withdrawal?

## Target
- File/function: `system-parachains/people/people-polkadot/src/xcm_config.rs` :: `LocationToAccountId`
- Entrypoint: `PeoplePolkadot::pallet_xcm::execute`
- Attacker controls: topic, query, and beneficiary fields that are replayed or reordered across otherwise valid XCM flows
- Exploit idea: forces the runtime to treat the same asset as local in one step and foreign, reserve-backed, or bridged in another
- Invariant to test: location-to-account conversion must stay injective enough for all accepted user and XCM flows
- Expected Immunefi impact: Critical - unbacked asset mint, unlock, or withdrawal
- Fast validation: xcm-emulator test that drives the exact signed or source-chain user path and asserts final origin plus asset balances
