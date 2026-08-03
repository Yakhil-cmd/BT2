# Q2482: collective-origin widening via polkadotxcm execute on Collectives Polkadot runtime

## Question
Can an unprivileged attacker enter through `PolkadotXcm::execute` on Collectives Polkadot runtime and control batched combinations of proxy, preimage, referenda, and XCM execution so that `construct_runtime! / RuntimeCall::{Alliance, FellowshipReferenda, AmbassadorReferenda, Preimage, Scheduler, Proxy, Utility, PolkadotXcm}` lets a preimage, deposit, or scheduled effect be consumed more than once or cleaned up too early, breaking the invariant that signed users must not escalate into privileged collective execution through batching, proxying, or XCM aliasing, and leading to critical - unauthorized privileged execution with direct user or treasury loss?

## Target
- File/function: `system-parachains/collectives/collectives-polkadot/src/lib.rs` :: `construct_runtime! / RuntimeCall::{Alliance, FellowshipReferenda, AmbassadorReferenda, Preimage, Scheduler, Proxy, Utility, PolkadotXcm}`
- Entrypoint: `PolkadotXcm::execute`
- Attacker controls: batched combinations of proxy, preimage, referenda, and XCM execution
- Exploit idea: lets a preimage, deposit, or scheduled effect be consumed more than once or cleaned up too early
- Invariant to test: signed users must not escalate into privileged collective execution through batching, proxying, or XCM aliasing
- Expected Immunefi impact: Critical - unauthorized privileged execution with direct user or treasury loss
- Fast validation: runtime integration test over preimage, submit, schedule, and cleanup ordering
