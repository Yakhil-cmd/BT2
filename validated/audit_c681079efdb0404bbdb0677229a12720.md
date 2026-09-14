Based on my research, I searched for parsing loops within Agave's reachable transaction-processing paths (precompiles, compute-budget instruction parsing, account/AppendVec loops, program-runtime serialization) that could mirror the FRR bug class of "a pointer not advancing causing an infinite loop." All loop-based parsers I found in scope enforce forward progress or bounds explicitly:

- `secp256k1::verify` and `ed25519::verify` iterate with `for i in 0..count`/`0..num_signatures`, a fixed range that always terminates regardless of data content. [1](#0-0) [2](#0-1) 
- `parse_batch_instruction` in transaction-status (RPC-only, explicitly out of scope) always advances `data_cursor` by at least 2 before any error path. [3](#0-2) 
- AppendVec's `scan_accounts_stored_meta`/`scan_stored_accounts_no_data` loops always call `reader.consume_or_skip(stored_size)` or `break` each iteration, and are operator/local-storage code, not attacker-reachable via a single transaction.
<invoke name="grep_search">
<parameter name="pattern">placeholder</parameter>
</invoke>

### Citations

**File:** precompiles/src/secp256k1.rs (L44-48)
```rust
    for i in 0..count {
        let start = i
            .saturating_mul(SIGNATURE_OFFSETS_SERIALIZED_SIZE)
            .saturating_add(1);
        let end = start.saturating_add(SIGNATURE_OFFSETS_SERIALIZED_SIZE);
```

**File:** precompiles/src/ed25519.rs (L30-33)
```rust
    for i in 0..num_signatures {
        let start = i
            .saturating_mul(SIGNATURE_OFFSETS_SERIALIZED_SIZE)
            .saturating_add(SIGNATURE_OFFSETS_START);
```

**File:** transaction-status/src/parse_token.rs (L779-785)
```rust
    while data_cursor < data.len() {
        let num_accounts = *data.get(data_cursor).ok_or_else(not_parsable)? as usize;
        let data_len = *data.get(data_cursor + 1).ok_or_else(not_parsable)? as usize;
        data_cursor += 2;
        let data_end = data_cursor.checked_add(data_len).ok_or_else(not_parsable)?;
        let inner_data = data.get(data_cursor..data_end).ok_or_else(not_parsable)?;
        data_cursor = data_end;
```
