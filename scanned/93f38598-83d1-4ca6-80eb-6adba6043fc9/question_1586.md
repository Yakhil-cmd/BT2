# Q1586: oversized receipt wedge in scheduler::get_final_granted_bandwidth

## Question
Can an unprivileged attacker who runs an attacker contract that emits receipts via `promise_batch_action_*` host calls, controlling a receipt larger than any single grant the scheduler can issue, drive `runtime/runtime/src/bandwidth_scheduler/scheduler.rs::get_final_granted_bandwidth` to create a receipt that can never be granted enough bandwidth to move, breaking the invariant that every admitted receipt can eventually be granted enough bandwidth to be sent, and leading to permanent freezing of funds?

## Target
- File/function: `runtime/runtime/src/bandwidth_scheduler/scheduler.rs` -> `get_final_granted_bandwidth`
- Entrypoint: unprivileged attacker runs an attacker contract that emits receipts via `promise_batch_action_*` host calls
- Attacker controls: a receipt larger than any single grant the scheduler can issue
- Exploit idea: create a receipt that can never be granted enough bandwidth to move
- Invariant to test: every admitted receipt can eventually be granted enough bandwidth to be sent
- Expected Immunefi impact: Critical - permanent freezing of funds
- Fast validation: write a multi-shard `test-loop-tests` scenario and assert every shard keeps producing chunks and all receipts drain
