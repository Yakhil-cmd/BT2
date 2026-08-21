# Q3335: rejection asymmetry in congestion_control::generate_bandwidth_requests

## Question
Can an unprivileged attacker who drives cross-shard traffic from many attacker-funded accounts on different shards, controlling traffic aimed at a shard right at the congestion rejection threshold, drive `runtime/runtime/src/congestion_control.rs::generate_bandwidth_requests` to get attacker receipts admitted while honest receipts are rejected, breaking the invariant that admission decisions do not depend on the sender's identity, and leading to permanent freezing of funds?

## Target
- File/function: `runtime/runtime/src/congestion_control.rs` -> `generate_bandwidth_requests`
- Entrypoint: unprivileged attacker drives cross-shard traffic from many attacker-funded accounts on different shards
- Attacker controls: traffic aimed at a shard right at the congestion rejection threshold
- Exploit idea: get attacker receipts admitted while honest receipts are rejected
- Invariant to test: admission decisions do not depend on the sender's identity
- Expected Immunefi impact: Critical - permanent freezing of funds
- Fast validation: write a multi-shard `test-loop-tests` scenario and assert every shard keeps producing chunks and all receipts drain
