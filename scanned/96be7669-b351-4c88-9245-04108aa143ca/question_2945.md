# Q2945: alias collision on execution via peoplekusama pallet xcm send on People Kusama XCM

## Question
Can an unprivileged attacker enter through `PeopleKusama::pallet_xcm::send` on People Kusama XCM and control an execution path that alternates between paid execution, explicitly unpaid execution, and refund handling so that `XcmOriginToTransactDispatchOrigin` reaches an exporter, alias, teleporter, or reserve path that should only be reachable from a tighter origin class, breaking the invariant that delivery, execution, and refund accounting must not let a user extract more value than was actually debited, and leading to critical - unauthorized local execution with direct loss of funds?

## Target
- File/function: `system-parachains/people/people-kusama/src/xcm_config.rs` :: `XcmOriginToTransactDispatchOrigin`
- Entrypoint: `PeopleKusama::pallet_xcm::send`
- Attacker controls: an execution path that alternates between paid execution, explicitly unpaid execution, and refund handling
- Exploit idea: reaches an exporter, alias, teleporter, or reserve path that should only be reachable from a tighter origin class
- Invariant to test: delivery, execution, and refund accounting must not let a user extract more value than was actually debited
- Expected Immunefi impact: Critical - unauthorized local execution with direct loss of funds
- Fast validation: xcm-emulator test that drives the exact signed or source-chain user path and asserts final origin plus asset balances
