# Q2430: collective-origin widening via preimage note preimage unnote on Collectives Polkadot runtime

## Question
Can an unprivileged attacker enter through `Preimage::{note_preimage, unnote_preimage}` on Collectives Polkadot runtime and control XCM messages and beneficiaries that interact with the same balance or scheduling state so that `construct_runtime! / RuntimeCall::{Alliance, FellowshipReferenda, AmbassadorReferenda, Preimage, Scheduler, Proxy, Utility, PolkadotXcm}` induces a state where execution succeeds but deposit, refund, or scheduling state remains inconsistent, breaking the invariant that XCM-assisted execution must not strand or duplicate collective-related funds, and leading to critical - unauthorized privileged execution with direct user or treasury loss?

## Target
- File/function: `system-parachains/collectives/collectives-polkadot/src/lib.rs` :: `construct_runtime! / RuntimeCall::{Alliance, FellowshipReferenda, AmbassadorReferenda, Preimage, Scheduler, Proxy, Utility, PolkadotXcm}`
- Entrypoint: `Preimage::{note_preimage, unnote_preimage}`
- Attacker controls: XCM messages and beneficiaries that interact with the same balance or scheduling state
- Exploit idea: induces a state where execution succeeds but deposit, refund, or scheduling state remains inconsistent
- Invariant to test: XCM-assisted execution must not strand or duplicate collective-related funds
- Expected Immunefi impact: Critical - unauthorized privileged execution with direct user or treasury loss
- Fast validation: stateful fuzz test over batched proxy/XCM/preimage combinations
