# Q2511: collective-origin widening via preimage note preimage unnote on Collectives Polkadot runtime

## Question
Can an unprivileged attacker enter through `Preimage::{note_preimage, unnote_preimage}` on Collectives Polkadot runtime and control preimages, deposits, and dispatchable calls whose execution is later scheduled or referendum-driven so that `impl_runtime_apis! / XCM payment and dry-run APIs` lets a preimage, deposit, or scheduled effect be consumed more than once or cleaned up too early, breaking the invariant that XCM-assisted execution must not strand or duplicate collective-related funds, and leading to critical - unauthorized privileged execution with direct user or treasury loss?

## Target
- File/function: `system-parachains/collectives/collectives-polkadot/src/lib.rs` :: `impl_runtime_apis! / XCM payment and dry-run APIs`
- Entrypoint: `Preimage::{note_preimage, unnote_preimage}`
- Attacker controls: preimages, deposits, and dispatchable calls whose execution is later scheduled or referendum-driven
- Exploit idea: lets a preimage, deposit, or scheduled effect be consumed more than once or cleaned up too early
- Invariant to test: XCM-assisted execution must not strand or duplicate collective-related funds
- Expected Immunefi impact: Critical - unauthorized privileged execution with direct user or treasury loss
- Fast validation: runtime integration test over preimage, submit, schedule, and cleanup ordering
