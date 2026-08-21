# Q1110: return-data plumbing in dependencies::set_refund_to

## Question
Can an unprivileged attacker who runs an attacker contract that emits receipts via `promise_batch_action_*` host calls, controlling return data sizes across a chain of callbacks, drive `runtime/near-vm-runner/src/logic/dependencies.rs::set_refund_to` to move more return data between receipts than is charged or bounded, breaking the invariant that return data is bounded and charged on every hop, and leading to greatly increasing the computational cost of the network (free or underpriced execution)?

## Target
- File/function: `runtime/near-vm-runner/src/logic/dependencies.rs` -> `set_refund_to`
- Entrypoint: unprivileged attacker runs an attacker contract that emits receipts via `promise_batch_action_*` host calls
- Attacker controls: return data sizes across a chain of callbacks
- Exploit idea: move more return data between receipts than is charged or bounded
- Invariant to test: return data is bounded and charged on every hop
- Expected Immunefi impact: High - greatly increasing the computational cost of the network (free or underpriced execution)
- Fast validation: add a case under `runtime/near-vm-runner/src/tests/` and diff burnt gas / outcome against the expected costs
