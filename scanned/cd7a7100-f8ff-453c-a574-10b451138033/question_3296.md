# Q3296: link monopolisation in scheduler::init_budgets

## Question
Can an unprivileged attacker who drives cross-shard traffic from many attacker-funded accounts on different shards, controlling many attacker accounts issuing requests on one link, drive `runtime/runtime/src/bandwidth_scheduler/scheduler.rs::init_budgets` to capture a link's entire bandwidth so honest receipts never move, breaking the invariant that bandwidth on a link is shared rather than captured by one sender, and leading to permanent freezing of funds?

## Target
- File/function: `runtime/runtime/src/bandwidth_scheduler/scheduler.rs` -> `init_budgets`
- Entrypoint: unprivileged attacker drives cross-shard traffic from many attacker-funded accounts on different shards
- Attacker controls: many attacker accounts issuing requests on one link
- Exploit idea: capture a link's entire bandwidth so honest receipts never move
- Invariant to test: bandwidth on a link is shared rather than captured by one sender
- Expected Immunefi impact: Critical - permanent freezing of funds
- Fast validation: write a multi-shard `test-loop-tests` scenario and assert every shard keeps producing chunks and all receipts drain
