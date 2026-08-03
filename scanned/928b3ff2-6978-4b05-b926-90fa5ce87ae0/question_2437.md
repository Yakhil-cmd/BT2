# Q2437: preimage-deposit drift via proxy proxy multisig as on Collectives Polkadot runtime

## Question
Can an unprivileged attacker enter through `Proxy::proxy` / `Multisig::as_multi` / `Utility::batch_all` on Collectives Polkadot runtime and control XCM messages and beneficiaries that interact with the same balance or scheduling state so that `construct_runtime! / RuntimeCall::{Alliance, FellowshipReferenda, AmbassadorReferenda, Preimage, Scheduler, Proxy, Utility, PolkadotXcm}` lets a preimage, deposit, or scheduled effect be consumed more than once or cleaned up too early, breaking the invariant that signed users must not escalate into privileged collective execution through batching, proxying, or XCM aliasing, and leading to high - severe scheduling or queue corruption with concrete protocol impact?

## Target
- File/function: `system-parachains/collectives/collectives-polkadot/src/lib.rs` :: `construct_runtime! / RuntimeCall::{Alliance, FellowshipReferenda, AmbassadorReferenda, Preimage, Scheduler, Proxy, Utility, PolkadotXcm}`
- Entrypoint: `Proxy::proxy` / `Multisig::as_multi` / `Utility::batch_all`
- Attacker controls: XCM messages and beneficiaries that interact with the same balance or scheduling state
- Exploit idea: lets a preimage, deposit, or scheduled effect be consumed more than once or cleaned up too early
- Invariant to test: signed users must not escalate into privileged collective execution through batching, proxying, or XCM aliasing
- Expected Immunefi impact: High - severe scheduling or queue corruption with concrete protocol impact
- Fast validation: stateful fuzz test over batched proxy/XCM/preimage combinations
