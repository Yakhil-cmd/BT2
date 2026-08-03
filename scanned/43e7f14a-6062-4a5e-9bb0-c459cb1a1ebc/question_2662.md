# Q2662: message-export route confusion via peoplepolkadot pallet xcm send on People Polkadot XCM

## Question
Can an unprivileged attacker enter through `PeoplePolkadot::pallet_xcm::send` on People Polkadot XCM and control an XCM payload with attacker-chosen origin-shaping instructions, fee asset, beneficiary, and nested `Transact` calls so that `LocationToAccountId` makes the barrier admit execution while the fee or asset path evaluates a different context than dispatch does, breaking the invariant that delivery, execution, and refund accounting must not let a user extract more value than was actually debited, and leading to high - stuck queue or persistent denial of service on a critical transfer path?

## Target
- File/function: `system-parachains/people/people-polkadot/src/xcm_config.rs` :: `LocationToAccountId`
- Entrypoint: `PeoplePolkadot::pallet_xcm::send`
- Attacker controls: an XCM payload with attacker-chosen origin-shaping instructions, fee asset, beneficiary, and nested `Transact` calls
- Exploit idea: makes the barrier admit execution while the fee or asset path evaluates a different context than dispatch does
- Invariant to test: delivery, execution, and refund accounting must not let a user extract more value than was actually debited
- Expected Immunefi impact: High - stuck queue or persistent denial of service on a critical transfer path
- Fast validation: targeted integration test proving whether the message can reach export, teleport, reserve, or transact paths it should never reach
