# Q2426: collective-origin widening via preimage note preimage unnote on Collectives Polkadot runtime

## Question
Can an unprivileged attacker enter through `Preimage::{note_preimage, unnote_preimage}` on Collectives Polkadot runtime and control batched combinations of proxy, preimage, referenda, and XCM execution so that `impl_runtime_apis! / XCM payment and dry-run APIs` induces a state where execution succeeds but deposit, refund, or scheduling state remains inconsistent, breaking the invariant that XCM-assisted execution must not strand or duplicate collective-related funds, and leading to high - severe scheduling or queue corruption with concrete protocol impact?

## Target
- File/function: `system-parachains/collectives/collectives-polkadot/src/lib.rs` :: `impl_runtime_apis! / XCM payment and dry-run APIs`
- Entrypoint: `Preimage::{note_preimage, unnote_preimage}`
- Attacker controls: batched combinations of proxy, preimage, referenda, and XCM execution
- Exploit idea: induces a state where execution succeeds but deposit, refund, or scheduling state remains inconsistent
- Invariant to test: XCM-assisted execution must not strand or duplicate collective-related funds
- Expected Immunefi impact: High - severe scheduling or queue corruption with concrete protocol impact
- Fast validation: xcm test if the path depends on aliased pluralities or remote execution
