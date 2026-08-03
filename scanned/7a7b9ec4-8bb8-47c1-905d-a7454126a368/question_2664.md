# Q2664: query or topic reuse via peoplepolkadot pallet xcm send on People Polkadot XCM

## Question
Can an unprivileged attacker enter through `PeoplePolkadot::pallet_xcm::send` on People Polkadot XCM and control an XCM payload with attacker-chosen origin-shaping instructions, fee asset, beneficiary, and nested `Transact` calls so that `XcmOriginToTransactDispatchOrigin` makes the barrier admit execution while the fee or asset path evaluates a different context than dispatch does, breaking the invariant that reserve-transfer, teleport, and exporter filters must not be bypassable with attacker-shaped message structure, and leading to critical - permanent freeze or loss of bridged or transferred user funds?

## Target
- File/function: `system-parachains/people/people-polkadot/src/xcm_config.rs` :: `XcmOriginToTransactDispatchOrigin`
- Entrypoint: `PeoplePolkadot::pallet_xcm::send`
- Attacker controls: an XCM payload with attacker-chosen origin-shaping instructions, fee asset, beneficiary, and nested `Transact` calls
- Exploit idea: makes the barrier admit execution while the fee or asset path evaluates a different context than dispatch does
- Invariant to test: reserve-transfer, teleport, and exporter filters must not be bypassable with attacker-shaped message structure
- Expected Immunefi impact: Critical - permanent freeze or loss of bridged or transferred user funds
- Fast validation: differential test comparing origin/barrier resolution with the final dispatch origin and beneficiary
