[1](#0-0) [2](#0-1)

### Citations

**File:** stackslib/src/chainstate/stacks/boot/pox-4.clar (L1-1)
```text
;; The .pox-4 contract
```

**File:** stackslib/src/chainstate/burn/operations/stack_stx.rs (L399-419)
```rust
    pub fn check(&self) -> Result<(), op_error> {
        if self.stacked_ustx == 0 {
            warn!("Invalid StackStxOp, must have positive ustx");
            return Err(op_error::StackStxMustBePositive);
        }

        if self.num_cycles == 0 || self.num_cycles > POX_MAX_NUM_CYCLES {
            warn!(
                "Invalid StackStxOp, num_cycles = {}, but must be in (0, {}]",
                self.num_cycles, POX_MAX_NUM_CYCLES
            );
        }

        // Check to see if the signer key is valid if available
        if let Some(signer_key) = &self.signer_key {
            Secp256k1PublicKey::from_slice(signer_key.as_bytes())
                .map_err(|_| op_error::StackStxInvalidKey)?;
        }

        Ok(())
    }
```
