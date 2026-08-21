# Q2116: bandwidth arithmetic overflow in bandwidth_scheduler::is_all_zeros

## Question
Can an unprivileged attacker who drives cross-shard traffic from many attacker-funded accounts on different shards, controlling accumulated request values driven toward integer bounds, drive `core/primitives/src/bandwidth_scheduler.rs::is_all_zeros` to overflow the scheduler's accounting into an inconsistent allocation, breaking the invariant that bandwidth accounting is exact for every reachable request set, and leading to unintended permanent chain split requiring a hard fork?

## Target
- File/function: `core/primitives/src/bandwidth_scheduler.rs` -> `is_all_zeros`
- Entrypoint: unprivileged attacker drives cross-shard traffic from many attacker-funded accounts on different shards
- Attacker controls: accumulated request values driven toward integer bounds
- Exploit idea: overflow the scheduler's accounting into an inconsistent allocation
- Invariant to test: bandwidth accounting is exact for every reachable request set
- Expected Immunefi impact: Critical - unintended permanent chain split requiring a hard fork
- Fast validation: add a proptest/invariant test that randomises the inputs and asserts the accounting identity holds for every generated case
