# Q2114: scheduler panic in bandwidth_scheduler::get_bit

## Question
Can an unprivileged attacker who drives cross-shard traffic from many attacker-funded accounts on different shards, controlling empty, maximal and duplicated request sets, drive `core/primitives/src/bandwidth_scheduler.rs::get_bit` to panic inside the scheduler on a request set an attacker can create, breaking the invariant that the scheduler handles every reachable request set without panicking, and leading to network unable to confirm new transactions (shard/chain halt)?

## Target
- File/function: `core/primitives/src/bandwidth_scheduler.rs` -> `get_bit`
- Entrypoint: unprivileged attacker drives cross-shard traffic from many attacker-funded accounts on different shards
- Attacker controls: empty, maximal and duplicated request sets
- Exploit idea: panic inside the scheduler on a request set an attacker can create
- Invariant to test: the scheduler handles every reachable request set without panicking
- Expected Immunefi impact: Critical - network unable to confirm new transactions (shard/chain halt)
- Fast validation: write a multi-shard `test-loop-tests` scenario and assert every shard keeps producing chunks and all receipts drain
