# Q3294: grant/send mismatch in scheduler::increase_allowance

## Question
Can an unprivileged attacker who runs an attacker contract that emits receipts via `promise_batch_action_*` host calls, controlling receipt sizes that differ between grant time and send time, drive `runtime/runtime/src/bandwidth_scheduler/scheduler.rs::increase_allowance` to send more bytes than the grant authorised, breaking the invariant that bytes sent on a link never exceed the bandwidth granted for it, and leading to greatly increasing the computational cost of the network (free or underpriced execution)?

## Target
- File/function: `runtime/runtime/src/bandwidth_scheduler/scheduler.rs` -> `increase_allowance`
- Entrypoint: unprivileged attacker runs an attacker contract that emits receipts via `promise_batch_action_*` host calls
- Attacker controls: receipt sizes that differ between grant time and send time
- Exploit idea: send more bytes than the grant authorised
- Invariant to test: bytes sent on a link never exceed the bandwidth granted for it
- Expected Immunefi impact: High - greatly increasing the computational cost of the network (free or underpriced execution)
- Fast validation: write a multi-shard `test-loop-tests` scenario and assert every shard keeps producing chunks and all receipts drain
