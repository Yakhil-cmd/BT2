# Q2475: schedule-cleanup mismatch via referenda signed submission and on Collectives Polkadot runtime

## Question
Can an unprivileged attacker enter through `Referenda` signed submission and deposit path on Collectives Polkadot runtime and control batched combinations of proxy, preimage, referenda, and XCM execution so that `construct_runtime! / RuntimeCall::{Alliance, FellowshipReferenda, AmbassadorReferenda, Preimage, Scheduler, Proxy, Utility, PolkadotXcm}` induces a state where execution succeeds but deposit, refund, or scheduling state remains inconsistent, breaking the invariant that scheduled or post-referendum consequences must stay bound to the exact authorized preimage and deposit state, and leading to critical - permanent freeze or misrouting of deposits tied to collective flows?

## Target
- File/function: `system-parachains/collectives/collectives-polkadot/src/lib.rs` :: `construct_runtime! / RuntimeCall::{Alliance, FellowshipReferenda, AmbassadorReferenda, Preimage, Scheduler, Proxy, Utility, PolkadotXcm}`
- Entrypoint: `Referenda` signed submission and deposit path
- Attacker controls: batched combinations of proxy, preimage, referenda, and XCM execution
- Exploit idea: induces a state where execution succeeds but deposit, refund, or scheduling state remains inconsistent
- Invariant to test: scheduled or post-referendum consequences must stay bound to the exact authorized preimage and deposit state
- Expected Immunefi impact: Critical - permanent freeze or misrouting of deposits tied to collective flows
- Fast validation: runtime integration test over preimage, submit, schedule, and cleanup ordering
