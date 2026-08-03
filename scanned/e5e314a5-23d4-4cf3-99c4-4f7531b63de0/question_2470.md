# Q2470: collective-origin widening via referenda signed submission and on Collectives Polkadot runtime

## Question
Can an unprivileged attacker enter through `Referenda` signed submission and deposit path on Collectives Polkadot runtime and control XCM messages and beneficiaries that interact with the same balance or scheduling state so that `impl_runtime_apis! / XCM payment and dry-run APIs` lets a preimage, deposit, or scheduled effect be consumed more than once or cleaned up too early, breaking the invariant that XCM-assisted execution must not strand or duplicate collective-related funds, and leading to critical - permanent freeze or misrouting of deposits tied to collective flows?

## Target
- File/function: `system-parachains/collectives/collectives-polkadot/src/lib.rs` :: `impl_runtime_apis! / XCM payment and dry-run APIs`
- Entrypoint: `Referenda` signed submission and deposit path
- Attacker controls: XCM messages and beneficiaries that interact with the same balance or scheduling state
- Exploit idea: lets a preimage, deposit, or scheduled effect be consumed more than once or cleaned up too early
- Invariant to test: XCM-assisted execution must not strand or duplicate collective-related funds
- Expected Immunefi impact: Critical - permanent freeze or misrouting of deposits tied to collective flows
- Fast validation: runtime integration test over preimage, submit, schedule, and cleanup ordering
