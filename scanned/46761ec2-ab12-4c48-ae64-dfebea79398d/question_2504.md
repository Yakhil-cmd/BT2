# Q2504: preimage-deposit drift via preimage note preimage unnote on Collectives Polkadot runtime

## Question
Can an unprivileged attacker enter through `Preimage::{note_preimage, unnote_preimage}` on Collectives Polkadot runtime and control preimages, deposits, and dispatchable calls whose execution is later scheduled or referendum-driven so that `construct_runtime! / RuntimeCall::{Alliance, FellowshipReferenda, AmbassadorReferenda, Preimage, Scheduler, Proxy, Utility, PolkadotXcm}` lets a preimage, deposit, or scheduled effect be consumed more than once or cleaned up too early, breaking the invariant that XCM-assisted execution must not strand or duplicate collective-related funds, and leading to critical - unauthorized privileged execution with direct user or treasury loss?

## Target
- File/function: `system-parachains/collectives/collectives-polkadot/src/lib.rs` :: `construct_runtime! / RuntimeCall::{Alliance, FellowshipReferenda, AmbassadorReferenda, Preimage, Scheduler, Proxy, Utility, PolkadotXcm}`
- Entrypoint: `Preimage::{note_preimage, unnote_preimage}`
- Attacker controls: preimages, deposits, and dispatchable calls whose execution is later scheduled or referendum-driven
- Exploit idea: lets a preimage, deposit, or scheduled effect be consumed more than once or cleaned up too early
- Invariant to test: XCM-assisted execution must not strand or duplicate collective-related funds
- Expected Immunefi impact: Critical - unauthorized privileged execution with direct user or treasury loss
- Fast validation: runtime integration test over preimage, submit, schedule, and cleanup ordering
