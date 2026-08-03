# Q2481: preimage-deposit drift via preimage note preimage unnote on Collectives Polkadot runtime

## Question
Can an unprivileged attacker enter through `Preimage::{note_preimage, unnote_preimage}` on Collectives Polkadot runtime and control preimages, deposits, and dispatchable calls whose execution is later scheduled or referendum-driven so that `impl_runtime_apis! / XCM payment and dry-run APIs` induces a state where execution succeeds but deposit, refund, or scheduling state remains inconsistent, breaking the invariant that signed users must not escalate into privileged collective execution through batching, proxying, or XCM aliasing, and leading to critical - unauthorized privileged execution with direct user or treasury loss?

## Target
- File/function: `system-parachains/collectives/collectives-polkadot/src/lib.rs` :: `impl_runtime_apis! / XCM payment and dry-run APIs`
- Entrypoint: `Preimage::{note_preimage, unnote_preimage}`
- Attacker controls: preimages, deposits, and dispatchable calls whose execution is later scheduled or referendum-driven
- Exploit idea: induces a state where execution succeeds but deposit, refund, or scheduling state remains inconsistent
- Invariant to test: signed users must not escalate into privileged collective execution through batching, proxying, or XCM aliasing
- Expected Immunefi impact: Critical - unauthorized privileged execution with direct user or treasury loss
- Fast validation: xcm test if the path depends on aliased pluralities or remote execution
