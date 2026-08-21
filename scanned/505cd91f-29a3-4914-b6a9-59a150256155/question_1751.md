# Q1751: prefetch amplification in prefetch::prefetch_sweat_record_batch

## Question
Can an unprivileged attacker who calls a deployed contract with a `FunctionCall` action carrying attacker-chosen arguments, controlling keys chosen so prefetching does far more IO than the call charges, drive `runtime/runtime/src/prefetch.rs::prefetch_sweat_record_batch` to force validators into unpaid disk work through the prefetcher, breaking the invariant that prefetch work is bounded by the gas the triggering receipt pays, and leading to greatly increasing the computational cost of the network (free or underpriced execution)?

## Target
- File/function: `runtime/runtime/src/prefetch.rs` -> `prefetch_sweat_record_batch`
- Entrypoint: unprivileged attacker calls a deployed contract with a `FunctionCall` action carrying attacker-chosen arguments
- Attacker controls: keys chosen so prefetching does far more IO than the call charges
- Exploit idea: force validators into unpaid disk work through the prefetcher
- Invariant to test: prefetch work is bounded by the gas the triggering receipt pays
- Expected Immunefi impact: High - greatly increasing the computational cost of the network (free or underpriced execution)
- Fast validation: write a multi-shard `test-loop-tests` scenario and assert every shard keeps producing chunks and all receipts drain
