# Q1598: request forgery in scheduler::process_bandwidth_requests

## Question
Can an unprivileged attacker who runs an attacker contract that emits receipts via `promise_batch_action_*` host calls, controlling the size and count of receipts that generate bandwidth requests, drive `runtime/runtime/src/bandwidth_scheduler/scheduler.rs::process_bandwidth_requests` to make the scheduler act on requests that do not reflect real queued receipts, breaking the invariant that bandwidth requests are derived only from real queued receipts, and leading to permanent freezing of funds?

## Target
- File/function: `runtime/runtime/src/bandwidth_scheduler/scheduler.rs` -> `process_bandwidth_requests`
- Entrypoint: unprivileged attacker runs an attacker contract that emits receipts via `promise_batch_action_*` host calls
- Attacker controls: the size and count of receipts that generate bandwidth requests
- Exploit idea: make the scheduler act on requests that do not reflect real queued receipts
- Invariant to test: bandwidth requests are derived only from real queued receipts
- Expected Immunefi impact: Critical - permanent freezing of funds
- Fast validation: write a multi-shard `test-loop-tests` scenario and assert every shard keeps producing chunks and all receipts drain
