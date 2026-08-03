# Q2520: preimage-deposit drift via polkadotxcm execute on Collectives Polkadot runtime

## Question
Can an unprivileged attacker enter through `PolkadotXcm::execute` on Collectives Polkadot runtime and control XCM messages and beneficiaries that interact with the same balance or scheduling state so that `construct_runtime! / RuntimeCall::{Alliance, FellowshipReferenda, AmbassadorReferenda, Preimage, Scheduler, Proxy, Utility, PolkadotXcm}` lets a preimage, deposit, or scheduled effect be consumed more than once or cleaned up too early, breaking the invariant that preimage and referendum-related deposits must be debited, refunded, and consumed exactly once, and leading to critical - permanent freeze or misrouting of deposits tied to collective flows?

## Target
- File/function: `system-parachains/collectives/collectives-polkadot/src/lib.rs` :: `construct_runtime! / RuntimeCall::{Alliance, FellowshipReferenda, AmbassadorReferenda, Preimage, Scheduler, Proxy, Utility, PolkadotXcm}`
- Entrypoint: `PolkadotXcm::execute`
- Attacker controls: XCM messages and beneficiaries that interact with the same balance or scheduling state
- Exploit idea: lets a preimage, deposit, or scheduled effect be consumed more than once or cleaned up too early
- Invariant to test: preimage and referendum-related deposits must be debited, refunded, and consumed exactly once
- Expected Immunefi impact: Critical - permanent freeze or misrouting of deposits tied to collective flows
- Fast validation: runtime integration test over preimage, submit, schedule, and cleanup ordering
