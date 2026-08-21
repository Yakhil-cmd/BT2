# Q3299: remaining-bandwidth rounding in scheduler::iter_links

## Question
Can an unprivileged attacker who drives cross-shard traffic from many attacker-funded accounts on different shards, controlling sizes chosen so leftover distribution rounds in the attacker's favour, drive `runtime/runtime/src/bandwidth_scheduler/scheduler.rs::iter_links` to accumulate free bandwidth from repeated rounding of the remainder, breaking the invariant that distributed bandwidth never exceeds the total available in any round, and leading to greatly increasing the computational cost of the network (free or underpriced execution)?

## Target
- File/function: `runtime/runtime/src/bandwidth_scheduler/scheduler.rs` -> `iter_links`
- Entrypoint: unprivileged attacker drives cross-shard traffic from many attacker-funded accounts on different shards
- Attacker controls: sizes chosen so leftover distribution rounds in the attacker's favour
- Exploit idea: accumulate free bandwidth from repeated rounding of the remainder
- Invariant to test: distributed bandwidth never exceeds the total available in any round
- Expected Immunefi impact: High - greatly increasing the computational cost of the network (free or underpriced execution)
- Fast validation: add a proptest/invariant test that randomises the inputs and asserts the accounting identity holds for every generated case
