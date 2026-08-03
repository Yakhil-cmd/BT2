# Q3012: fee-asset undercharge path via peoplekusama pallet xcm send on People Kusama XCM

## Question
Can an unprivileged attacker enter through `PeopleKusama::pallet_xcm::send` on People Kusama XCM and control an XCM payload with attacker-chosen origin-shaping instructions, fee asset, beneficiary, and nested `Transact` calls so that `FeeManager / SendXcmOrigin` induces a state where execution succeeds but assets are trapped, miscredited, replayed, or double-accounted across local and remote representations, breaking the invariant that signed users and user-controlled remote messages must never obtain Root, system-parachain, relay, or privileged plurality execution, and leading to critical - unbacked asset mint, unlock, or withdrawal?

## Target
- File/function: `system-parachains/people/people-kusama/src/xcm_config.rs` :: `FeeManager / SendXcmOrigin`
- Entrypoint: `PeopleKusama::pallet_xcm::send`
- Attacker controls: an XCM payload with attacker-chosen origin-shaping instructions, fee asset, beneficiary, and nested `Transact` calls
- Exploit idea: induces a state where execution succeeds but assets are trapped, miscredited, replayed, or double-accounted across local and remote representations
- Invariant to test: signed users and user-controlled remote messages must never obtain Root, system-parachain, relay, or privileged plurality execution
- Expected Immunefi impact: Critical - unbacked asset mint, unlock, or withdrawal
- Fast validation: stateful fuzz test over location, asset, and beneficiary permutations with assertions on issuance and backing
