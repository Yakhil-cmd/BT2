# Q382: rejection asymmetry in congestion_info::validate_extra_and_header

## Question
Can an unprivileged attacker who drives cross-shard traffic from many attacker-funded accounts on different shards, controlling traffic aimed at a shard right at the congestion rejection threshold, drive `core/primitives/src/congestion_info.rs::validate_extra_and_header` to get attacker receipts admitted while honest receipts are rejected, breaking the invariant that admission decisions do not depend on the sender's identity, and leading to permanent freezing of funds?

## Target
- File/function: `core/primitives/src/congestion_info.rs` -> `validate_extra_and_header`
- Entrypoint: unprivileged attacker drives cross-shard traffic from many attacker-funded accounts on different shards
- Attacker controls: traffic aimed at a shard right at the congestion rejection threshold
- Exploit idea: get attacker receipts admitted while honest receipts are rejected
- Invariant to test: admission decisions do not depend on the sender's identity
- Expected Immunefi impact: Critical - permanent freezing of funds
- Fast validation: write a multi-shard `test-loop-tests` scenario and assert every shard keeps producing chunks and all receipts drain
