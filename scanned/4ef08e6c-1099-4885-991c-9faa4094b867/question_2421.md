# Q2421: preimage-deposit drift via preimage note preimage unnote on Collectives Polkadot runtime

## Question
Can an unprivileged attacker enter through `Preimage::{note_preimage, unnote_preimage}` on Collectives Polkadot runtime and control XCM messages and beneficiaries that interact with the same balance or scheduling state so that `construct_runtime! / RuntimeCall::{Alliance, FellowshipReferenda, AmbassadorReferenda, Preimage, Scheduler, Proxy, Utility, PolkadotXcm}` creates a path where a signed user indirectly reaches a more privileged origin or wider call surface than intended, breaking the invariant that preimage and referendum-related deposits must be debited, refunded, and consumed exactly once, and leading to high - severe scheduling or queue corruption with concrete protocol impact?

## Target
- File/function: `system-parachains/collectives/collectives-polkadot/src/lib.rs` :: `construct_runtime! / RuntimeCall::{Alliance, FellowshipReferenda, AmbassadorReferenda, Preimage, Scheduler, Proxy, Utility, PolkadotXcm}`
- Entrypoint: `Preimage::{note_preimage, unnote_preimage}`
- Attacker controls: XCM messages and beneficiaries that interact with the same balance or scheduling state
- Exploit idea: creates a path where a signed user indirectly reaches a more privileged origin or wider call surface than intended
- Invariant to test: preimage and referendum-related deposits must be debited, refunded, and consumed exactly once
- Expected Immunefi impact: High - severe scheduling or queue corruption with concrete protocol impact
- Fast validation: xcm test if the path depends on aliased pluralities or remote execution
