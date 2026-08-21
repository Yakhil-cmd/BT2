# Q416: view/consensus divergence in receipt::refund_to

## Question
Can an unprivileged attacker who issues unauthenticated JSON-RPC queries against a public node, controlling payloads whose view representation differs from the consensus one, drive `core/primitives/src/receipt.rs::refund_to` to have the view layer report state that differs from consensus state, breaking the invariant that view types faithfully represent the underlying consensus state, and leading to unauthorized state modification of an account the attacker does not control?

## Target
- File/function: `core/primitives/src/receipt.rs` -> `refund_to`
- Entrypoint: unprivileged attacker issues unauthenticated JSON-RPC queries against a public node
- Attacker controls: payloads whose view representation differs from the consensus one
- Exploit idea: have the view layer report state that differs from consensus state
- Invariant to test: view types faithfully represent the underlying consensus state
- Expected Immunefi impact: Critical - unauthorized state modification of an account the attacker does not control
- Fast validation: drive the endpoint from `integration-tests` with the crafted payload and assert a typed error, not a panic or unbounded allocation
