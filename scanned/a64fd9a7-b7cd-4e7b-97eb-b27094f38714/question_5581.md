# Q5581: start http for readonly debug querying resource limit enforcement

## Question

What can an unprivileged user do by calling a public RPC method or submitting a signed transaction through broadcast_tx_* or query endpoints so that `start_http_for_readonly_debug_querying` in `chain/jsonrpc/src/lib.rs` processes large transactions, WASM bytecode, method args, access-key lists, receipts, RPC parameters, and storage writes along the RPC validation and forwarding path? User controls large transactions, WASM bytecode, method args, access-key lists, receipts, RPC parameters, and storage writes -> `start_http_for_readonly_debug_querying` processes that value during RPC admission, transaction validation, VM preparation/execution, trie access, and block/chunk resource accounting -> the user-controlled work is bounded by protocol gas, byte-size, recursion, proof, and queue limits before it can degrade consensus processing invariant might break -> potential in-scope impact is accepted non-network DoS, fee bypass, or consensus processing failure under the NEAR HackenProof scope. Exploit hypothesis: a valid user payload can drive this code into superlinear work or unbounded memory without paying the corresponding protocol cost, violating the actual protocol invariant that user-controlled work is bounded by protocol gas, byte-size, recursion, proof, and queue limits before it can degrade consensus processing.

## Target

- File/function: chain/jsonrpc/src/lib.rs:3120::start_http_for_readonly_debug_querying
- Entrypoint: public JSON-RPC request handled by chain/jsonrpc/src/lib.rs::JsonRpcHandler::process
- User-controlled input: large transactions, WASM bytecode, method args, access-key lists, receipts, RPC parameters, and storage writes
- Attack path: User controls large transactions, WASM bytecode, method args, access-key lists, receipts, RPC parameters, and storage writes -> public entrypoint reaches `start_http_for_readonly_debug_querying` -> RPC admission, transaction validation, VM preparation/execution, trie access, and block/chunk resource accounting handles the value -> invariant failure could produce accepted non-network DoS, fee bypass, or consensus processing failure
- Security invariant: user-controlled work is bounded by protocol gas, byte-size, recursion, proof, and queue limits before it can degrade consensus processing
- Expected bounty impact: accepted non-network DoS, fee bypass, or consensus processing failure
- Fast validation approach: fuzz maximum-size payloads and worst-case storage/receipt patterns on a private testnet while asserting deterministic rejection or bounded gas-charged execution
