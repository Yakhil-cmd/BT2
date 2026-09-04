[File: stackslib/src/chainstate/burn/operations/delegate_stx.rs -> Scope: Critical] Target: DelegateStxOp::parse_from_tx delegate_to derivation. Attacker action: submit a DelegateStxOp whose first output (delegate_to) is coerced via coerce_hash_mode/try_into_stacks_address to an address the attacker does not control, while sender is the attacker's own PreStx

### Citations

**File:** stackslib/src/chainstate/burn/operations/stack_stx.rs (L176-230)
```rust
    fn parse_data(data: &[u8]) -> Option<ParsedData> {
        /*
            Wire format:
            0      2  3                             19           20                  53                 69                        73
            |------|--|-----------------------------|------------|-------------------|-------------------|-------------------------|
            magic  op         uSTX to lock (u128)     cycles (u8)     signer key (optional)   max_amount (optional u128)  auth_id (optional u32)

             Note that `data` is missing the first 3 bytes -- the magic and op have been stripped

             The values ustx to lock and cycles are in big-endian order.

             parent-delta and parent-txoff will both be 0 if this block builds off of the genesis block.
        */

        if data.len() < 17 {
            // too short
            warn!(
