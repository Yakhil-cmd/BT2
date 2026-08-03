# Q2422: collective-origin widening via preimage note preimage unnote on Collectives Polkadot runtime

## Question
Can an unprivileged attacker enter through `Preimage::{note_preimage, unnote_preimage}` on Collectives Polkadot runtime and control preimages, deposits, and dispatchable calls whose execution is later scheduled or referendum-driven so that `construct_runtime! / RuntimeCall::{Alliance, FellowshipReferenda, AmbassadorReferenda, Preimage, Scheduler, Proxy, Utility, PolkadotXcm}` makes open user submission paths disagree with later dispatch, deposit, or cleanup logic about what was authorized, breaking the invariant that preimage and referendum-related deposits must be debited, refunded, and consumed exactly once, and leading to high - severe scheduling or queue corruption with concrete protocol impact?

## Target
- File/function: `system-parachains/collectives/collectives-polkadot/src/lib.rs` :: `construct_runtime! / RuntimeCall::{Alliance, FellowshipReferenda, AmbassadorReferenda, Preimage, Scheduler, Proxy, Utility, PolkadotXcm}`
- Entrypoint: `Preimage::{note_preimage, unnote_preimage}`
- Attacker controls: preimages, deposits, and dispatchable calls whose execution is later scheduled or referendum-driven
- Exploit idea: makes open user submission paths disagree with later dispatch, deposit, or cleanup logic about what was authorized
- Invariant to test: preimage and referendum-related deposits must be debited, refunded, and consumed exactly once
- Expected Immunefi impact: High - severe scheduling or queue corruption with concrete protocol impact
- Fast validation: runtime integration test over preimage, submit, schedule, and cleanup ordering
