# Q2702: message-export route confusion via peoplepolkadot pallet xcm execute on People Polkadot XCM

## Question
Can an unprivileged attacker enter through `PeoplePolkadot::pallet_xcm::execute` on People Polkadot XCM and control topic, query, and beneficiary fields that are replayed or reordered across otherwise valid XCM flows so that `LocationToAccountId` reaches an exporter, alias, teleporter, or reserve path that should only be reachable from a tighter origin class, breaking the invariant that asset backing must remain consistent across local balances, foreign assets, pool assets, reserve-backed assets, and bridged representations, and leading to critical - permanent freeze or loss of bridged or transferred user funds?

## Target
- File/function: `system-parachains/people/people-polkadot/src/xcm_config.rs` :: `LocationToAccountId`
- Entrypoint: `PeoplePolkadot::pallet_xcm::execute`
- Attacker controls: topic, query, and beneficiary fields that are replayed or reordered across otherwise valid XCM flows
- Exploit idea: reaches an exporter, alias, teleporter, or reserve path that should only be reachable from a tighter origin class
- Invariant to test: asset backing must remain consistent across local balances, foreign assets, pool assets, reserve-backed assets, and bridged representations
- Expected Immunefi impact: Critical - permanent freeze or loss of bridged or transferred user funds
- Fast validation: targeted integration test proving whether the message can reach export, teleport, reserve, or transact paths it should never reach
