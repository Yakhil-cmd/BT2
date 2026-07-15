# Q4395: should update outgoing metadatas receipt ordering invariant

## Question

What can an unprivileged user do by submitting encoded transactions, receipts created by contracts, account IDs, proofs, and JSON/RPC parameters so that `should_update_outgoing_metadatas` in `core/primitives/src/receipt.rs` (impl ReceiptOrStateStoredReceipt<'_>) processes a contract-created promise graph, receiver account IDs, callback dependencies, and attached gas along the protocol primitive validation, hashing, and serialization path? User controls a contract-created promise graph, receiver account IDs, callback dependencies, and attached gas -> `should_update_outgoing_metadatas` processes that value during receipt creation, local execution, incoming receipt application, and delayed queue draining -> the receipt ordering preserves dependency edges, shard routing, and exactly-once execution invariant might break -> potential in-scope impact is transaction manipulation, balance manipulation, or contract execution flow corruption under the NEAR HackenProof scope. Exploit hypothesis: a user-shaped promise DAG can make this code accept or execute receipts in an order that breaks dependency preservation and changes balances or callback results, violating the actual protocol invariant that receipt ordering preserves dependency edges, shard routing, and exactly-once execution.

## Target

- File/function: core/primitives/src/receipt.rs:169::should_update_outgoing_metadatas
- Entrypoint: public RPC transaction/query input decoded into core/primitives protocol objects
- User-controlled input: a contract-created promise graph, receiver account IDs, callback dependencies, and attached gas
- Attack path: User controls a contract-created promise graph, receiver account IDs, callback dependencies, and attached gas -> public entrypoint reaches `should_update_outgoing_metadatas` -> receipt creation, local execution, incoming receipt application, and delayed queue draining handles the value -> invariant failure could produce transaction manipulation, balance manipulation, or contract execution flow corruption
- Security invariant: receipt ordering preserves dependency edges, shard routing, and exactly-once execution
- Expected bounty impact: transaction manipulation, balance manipulation, or contract execution flow corruption
- Fast validation approach: build a test-loop scenario with cross-shard promises, callbacks, refunds, and delayed receipts, then compare outcomes, receipt IDs, and final state roots across nodes
