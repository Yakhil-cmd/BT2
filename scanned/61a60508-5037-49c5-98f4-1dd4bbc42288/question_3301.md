# Q3301: scheduler starvation in scheduler::process_bandwidth_requests

## Question
Can an unprivileged attacker who drives cross-shard traffic from many attacker-funded accounts on different shards, controlling a request pattern that keeps one link permanently at the back of the allocation order, drive `runtime/runtime/src/bandwidth_scheduler/scheduler.rs::process_bandwidth_requests` to permanently starve one shard link of bandwidth, breaking the invariant that every link with pending receipts eventually receives bandwidth, and leading to permanent freezing of funds?

## Target
- File/function: `runtime/runtime/src/bandwidth_scheduler/scheduler.rs` -> `process_bandwidth_requests`
- Entrypoint: unprivileged attacker drives cross-shard traffic from many attacker-funded accounts on different shards
- Attacker controls: a request pattern that keeps one link permanently at the back of the allocation order
- Exploit idea: permanently starve one shard link of bandwidth
- Invariant to test: every link with pending receipts eventually receives bandwidth
- Expected Immunefi impact: Critical - permanent freezing of funds
- Fast validation: write a multi-shard `test-loop-tests` scenario and assert every shard keeps producing chunks and all receipts drain
