# Q1705: code identity across shards in global_contracts::apply_global_contract_distribution_receipt

## Question
Can an unprivileged attacker who drives cross-shard traffic from many attacker-funded accounts on different shards, controlling the same global contract referenced from accounts on different shards, drive `runtime/runtime/src/global_contracts.rs::apply_global_contract_distribution_receipt` to have shards disagree about the code behind one identifier, breaking the invariant that all shards resolve a global contract identifier identically, and leading to unintended permanent chain split requiring a hard fork?

## Target
- File/function: `runtime/runtime/src/global_contracts.rs` -> `apply_global_contract_distribution_receipt`
- Entrypoint: unprivileged attacker drives cross-shard traffic from many attacker-funded accounts on different shards
- Attacker controls: the same global contract referenced from accounts on different shards
- Exploit idea: have shards disagree about the code behind one identifier
- Invariant to test: all shards resolve a global contract identifier identically
- Expected Immunefi impact: Critical - unintended permanent chain split requiring a hard fork
- Fast validation: run the same chunk through both execution paths and assert identical state root, gas burnt and outcome ids
