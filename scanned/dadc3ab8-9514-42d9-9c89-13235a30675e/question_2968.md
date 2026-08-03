# Q2968: query or topic reuse via peoplekusama pallet xcm execute on People Kusama XCM

## Question
Can an unprivileged attacker enter through `PeopleKusama::pallet_xcm::execute` on People Kusama XCM and control an XCM payload with attacker-chosen origin-shaping instructions, fee asset, beneficiary, and nested `Transact` calls so that `LocationToAccountId` makes the barrier admit execution while the fee or asset path evaluates a different context than dispatch does, breaking the invariant that location-to-account conversion must stay injective enough for all accepted user and XCM flows, and leading to critical - unbacked asset mint, unlock, or withdrawal?

## Target
- File/function: `system-parachains/people/people-kusama/src/xcm_config.rs` :: `LocationToAccountId`
- Entrypoint: `PeopleKusama::pallet_xcm::execute`
- Attacker controls: an XCM payload with attacker-chosen origin-shaping instructions, fee asset, beneficiary, and nested `Transact` calls
- Exploit idea: makes the barrier admit execution while the fee or asset path evaluates a different context than dispatch does
- Invariant to test: location-to-account conversion must stay injective enough for all accepted user and XCM flows
- Expected Immunefi impact: Critical - unbacked asset mint, unlock, or withdrawal
- Fast validation: stateful fuzz test over location, asset, and beneficiary permutations with assertions on issuance and backing
