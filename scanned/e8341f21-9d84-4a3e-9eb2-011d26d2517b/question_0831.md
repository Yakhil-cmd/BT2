# Q831: iterator skipping in iter::visit_nodes_interval

## Question
Can an unprivileged attacker who issues unauthenticated JSON-RPC queries against a public node, controlling prefixes and bounds that stress iterator seek logic, drive `core/store/src/trie/ops/iter.rs::visit_nodes_interval` to skip or repeat entries during iteration in a way that misreports state, breaking the invariant that iteration visits every key in range exactly once, and leading to unauthorized state modification of an account the attacker does not control?

## Target
- File/function: `core/store/src/trie/ops/iter.rs` -> `visit_nodes_interval`
- Entrypoint: unprivileged attacker issues unauthenticated JSON-RPC queries against a public node
- Attacker controls: prefixes and bounds that stress iterator seek logic
- Exploit idea: skip or repeat entries during iteration in a way that misreports state
- Invariant to test: iteration visits every key in range exactly once
- Expected Immunefi impact: Critical - unauthorized state modification of an account the attacker does not control
- Fast validation: write a `core/store` trie unit test over adversarial key/value pairs and assert lookups, deletes and refcounts stay consistent
