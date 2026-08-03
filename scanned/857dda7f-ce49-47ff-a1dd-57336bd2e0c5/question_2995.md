# Q2995: alias collision on execution via peoplekusama pallet xcm execute on People Kusama XCM

## Question
Can an unprivileged attacker enter through `PeopleKusama::pallet_xcm::execute` on People Kusama XCM and control an XCM payload with attacker-chosen origin-shaping instructions, fee asset, beneficiary, and nested `Transact` calls so that `LocationToAccountId` makes the barrier admit execution while the fee or asset path evaluates a different context than dispatch does, breaking the invariant that the same XCM message must never be treated as both paid and fee-waived for the same execution path, and leading to critical - permanent freeze or loss of bridged or transferred user funds?

## Target
- File/function: `system-parachains/people/people-kusama/src/xcm_config.rs` :: `LocationToAccountId`
- Entrypoint: `PeopleKusama::pallet_xcm::execute`
- Attacker controls: an XCM payload with attacker-chosen origin-shaping instructions, fee asset, beneficiary, and nested `Transact` calls
- Exploit idea: makes the barrier admit execution while the fee or asset path evaluates a different context than dispatch does
- Invariant to test: the same XCM message must never be treated as both paid and fee-waived for the same execution path
- Expected Immunefi impact: Critical - permanent freeze or loss of bridged or transferred user funds
- Fast validation: differential test comparing origin/barrier resolution with the final dispatch origin and beneficiary
