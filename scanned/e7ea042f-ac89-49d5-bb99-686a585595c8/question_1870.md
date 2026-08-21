# Q1870: tx submission amplification in lib::handle_entity_debug_readonly

## Question
Can an unprivileged attacker who issues unauthenticated JSON-RPC queries against a public node, controlling a stream of transactions that are expensive to validate and always rejected, drive `chain/jsonrpc/src/lib.rs::handle_entity_debug_readonly` to impose validation cost on the node without paying any fee, breaking the invariant that rejected transactions cost the node less than they cost the sender, and leading to griefing / validator resource exhaustion with no direct profit?

## Target
- File/function: `chain/jsonrpc/src/lib.rs` -> `handle_entity_debug_readonly`
- Entrypoint: unprivileged attacker issues unauthenticated JSON-RPC queries against a public node
- Attacker controls: a stream of transactions that are expensive to validate and always rejected
- Exploit idea: impose validation cost on the node without paying any fee
- Invariant to test: rejected transactions cost the node less than they cost the sender
- Expected Immunefi impact: Medium - griefing / validator resource exhaustion with no direct profit
- Fast validation: drive the endpoint from `integration-tests` with the crafted payload and assert a typed error, not a panic or unbounded allocation
