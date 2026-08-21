# Q339: bandwidth grant inflation in bandwidth_scheduler::calculate

## Question
Can an unprivileged attacker who drives cross-shard traffic from many attacker-funded accounts on different shards, controlling bandwidth requests crafted to claim more than the shard's fair allocation, drive `core/primitives/src/bandwidth_scheduler.rs::calculate` to obtain a bandwidth grant larger than the scheduler should ever issue, breaking the invariant that granted bandwidth per shard never exceeds the configured limit, and leading to network unable to confirm new transactions (shard/chain halt)?

## Target
- File/function: `core/primitives/src/bandwidth_scheduler.rs` -> `calculate`
- Entrypoint: unprivileged attacker drives cross-shard traffic from many attacker-funded accounts on different shards
- Attacker controls: bandwidth requests crafted to claim more than the shard's fair allocation
- Exploit idea: obtain a bandwidth grant larger than the scheduler should ever issue
- Invariant to test: granted bandwidth per shard never exceeds the configured limit
- Expected Immunefi impact: Critical - network unable to confirm new transactions (shard/chain halt)
- Fast validation: write a multi-shard `test-loop-tests` scenario and assert every shard keeps producing chunks and all receipts drain
