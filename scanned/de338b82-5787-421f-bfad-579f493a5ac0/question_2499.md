# Q2499: schedule-cleanup mismatch via preimage note preimage unnote on Collectives Polkadot runtime

## Question
Can an unprivileged attacker enter through `Preimage::{note_preimage, unnote_preimage}` on Collectives Polkadot runtime and control batched combinations of proxy, preimage, referenda, and XCM execution so that `impl_runtime_apis! / XCM payment and dry-run APIs` creates a path where a signed user indirectly reaches a more privileged origin or wider call surface than intended, breaking the invariant that signed users must not escalate into privileged collective execution through batching, proxying, or XCM aliasing, and leading to high - severe scheduling or queue corruption with concrete protocol impact?

## Target
- File/function: `system-parachains/collectives/collectives-polkadot/src/lib.rs` :: `impl_runtime_apis! / XCM payment and dry-run APIs`
- Entrypoint: `Preimage::{note_preimage, unnote_preimage}`
- Attacker controls: batched combinations of proxy, preimage, referenda, and XCM execution
- Exploit idea: creates a path where a signed user indirectly reaches a more privileged origin or wider call surface than intended
- Invariant to test: signed users must not escalate into privileged collective execution through batching, proxying, or XCM aliasing
- Expected Immunefi impact: High - severe scheduling or queue corruption with concrete protocol impact
- Fast validation: runtime integration test over preimage, submit, schedule, and cleanup ordering
