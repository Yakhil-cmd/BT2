# Q3303: request forgery in scheduler::schedule_bandwidth

## Question
Can an unprivileged attacker who runs an attacker contract that emits receipts via `promise_batch_action_*` host calls, controlling the size and count of receipts that generate bandwidth requests, drive `runtime/runtime/src/bandwidth_scheduler/scheduler.rs::schedule_bandwidth` to make the scheduler act on requests that do not reflect real queued receipts, breaking the invariant that bandwidth requests are derived only from real queued receipts, and leading to permanent freezing of funds?

## Target
- File/function: `runtime/runtime/src/bandwidth_scheduler/scheduler.rs` -> `schedule_bandwidth`
- Entrypoint: unprivileged attacker runs an attacker contract that emits receipts via `promise_batch_action_*` host calls
- Attacker controls: the size and count of receipts that generate bandwidth requests
- Exploit idea: make the scheduler act on requests that do not reflect real queued receipts
- Invariant to test: bandwidth requests are derived only from real queued receipts
- Expected Immunefi impact: Critical - permanent freezing of funds
- Fast validation: write a multi-shard `test-loop-tests` scenario and assert every shard keeps producing chunks and all receipts drain
