# Q617: code identity across shards in contract::record_call

## Question
Can an unprivileged attacker who drives cross-shard traffic from many attacker-funded accounts on different shards, controlling the same global contract referenced from accounts on different shards, drive `core/store/src/contract.rs::record_call` to have shards disagree about the code behind one identifier, breaking the invariant that all shards resolve a global contract identifier identically, and leading to unintended permanent chain split requiring a hard fork?

## Target
- File/function: `core/store/src/contract.rs` -> `record_call`
- Entrypoint: unprivileged attacker drives cross-shard traffic from many attacker-funded accounts on different shards
- Attacker controls: the same global contract referenced from accounts on different shards
- Exploit idea: have shards disagree about the code behind one identifier
- Invariant to test: all shards resolve a global contract identifier identically
- Expected Immunefi impact: Critical - unintended permanent chain split requiring a hard fork
- Fast validation: run the same chunk through both execution paths and assert identical state root, gas burnt and outcome ids
