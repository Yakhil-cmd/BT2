# Q3902: delayed-receipt starvation in adapter::view_access_key

## Question
Can an unprivileged attacker who drives cross-shard traffic from many attacker-funded accounts on different shards, controlling a sustained flood of receipts into one shard's delayed queue, drive `runtime/runtime/src/adapter.rs::view_access_key` to keep a victim's receipts permanently behind attacker receipts in the delayed queue, breaking the invariant that every accepted receipt is eventually processed in bounded time, and leading to permanent freezing of funds?

## Target
- File/function: `runtime/runtime/src/adapter.rs` -> `view_access_key`
- Entrypoint: unprivileged attacker drives cross-shard traffic from many attacker-funded accounts on different shards
- Attacker controls: a sustained flood of receipts into one shard's delayed queue
- Exploit idea: keep a victim's receipts permanently behind attacker receipts in the delayed queue
- Invariant to test: every accepted receipt is eventually processed in bounded time
- Expected Immunefi impact: Critical - permanent freezing of funds
- Fast validation: write a multi-shard `test-loop-tests` scenario and assert every shard keeps producing chunks and all receipts drain
