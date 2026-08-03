# Q2435: schedule-cleanup mismatch via preimage note preimage unnote on Collectives Polkadot runtime

## Question
Can an unprivileged attacker enter through `Preimage::{note_preimage, unnote_preimage}` on Collectives Polkadot runtime and control user-controlled inputs that feed plurality-like execution or post-deposit cleanup logic so that `impl_runtime_apis! / XCM payment and dry-run APIs` lets a preimage, deposit, or scheduled effect be consumed more than once or cleaned up too early, breaking the invariant that scheduled or post-referendum consequences must stay bound to the exact authorized preimage and deposit state, and leading to critical - unauthorized privileged execution with direct user or treasury loss?

## Target
- File/function: `system-parachains/collectives/collectives-polkadot/src/lib.rs` :: `impl_runtime_apis! / XCM payment and dry-run APIs`
- Entrypoint: `Preimage::{note_preimage, unnote_preimage}`
- Attacker controls: user-controlled inputs that feed plurality-like execution or post-deposit cleanup logic
- Exploit idea: lets a preimage, deposit, or scheduled effect be consumed more than once or cleaned up too early
- Invariant to test: scheduled or post-referendum consequences must stay bound to the exact authorized preimage and deposit state
- Expected Immunefi impact: Critical - unauthorized privileged execution with direct user or treasury loss
- Fast validation: stateful fuzz test over batched proxy/XCM/preimage combinations
