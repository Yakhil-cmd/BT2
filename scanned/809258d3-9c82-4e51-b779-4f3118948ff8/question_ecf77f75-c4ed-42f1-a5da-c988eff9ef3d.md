Target: DelegateStxOp::parse_from_tx delegate_to derivation (delegate_stx.rs:158-170). Attacker action: craft a Bitcoin tx whose first output's address, after coerce_hash_mode() and try_into_stacks_address(), collides with the attacker's own address rather than the intended pool/signer address, then separately claim (off-chain) that this DelegateStxOp authorizes a specific pool to stack on their behalf while delegate_to actually resolves to themselves. Preconditions: attacker fully controls both the DelegateStxOp's output encoding and any off-chain claims about intended delegate_to. Call sequence: parse_from_tx

### Citations

**File:** stackslib/src/chainstate/burn/operations/stack_stx.rs (L398-419)
```rust
impl StackStxOp {
    pub fn check(&self) -> Result<(), op_error> {
        if self.stacked_ustx == 0 {
            warn!(
