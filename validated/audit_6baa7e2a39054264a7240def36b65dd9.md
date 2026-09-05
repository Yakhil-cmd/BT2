### Title
Missing validation of `num_cycles` bounds in `StackStxOp::check` allows burn-chain stack-stx operations with out-of-range lock periods to pass validation - (File: `stackslib/src/chainstate/burn/operations/stack_stx.rs`)

### Summary
`StackStxOp::check()` is supposed to reject any `stack-stx` burnchain operation whose `num_cycles` field is `0` or greater than `POX_MAX_NUM_CYCLES`. The `if` branch that detects this condition only logs a `warn!` and falls through — it never returns an `Err`, so execution continues to the final `Ok(())`. This means a stacker can submit a Bitcoin `StackStxOp` with an arbitrary, out-of-range `num_cycles` value and have it accepted as a syntactically valid stacking operation.

### Finding Description
`StackStxOp::parse_data` extracts `num_cycles` directly from untrusted bytes taken from a Bitcoin transaction's OP_RETURN payload with no bound checking beyond being a single byte (0-255): [1](#0-0) 

The only place `num_cycles` is supposed to be range-checked before the op is treated as valid is `StackStxOp::check()`: [2](#0-1) 

Compare the `stacked_ustx == 0` branch, which correctly returns `Err(op_error::StackStxMustBePositive)`, to the `num_cycles` branch immediately below it, which only calls `warn!` and has no `return Err(...)` — execution simply continues to `Ok(())` at the end of the function. This is precisely the "parsed without validation" bug class from the external report: data taken from an external/untrusted source (a Bitcoin transaction, analogous to "JSON data from responses") is decoded and then a check that looks like a validation step is present in the source but is not actually enforced, so malformed/out-of-range values are silently accepted downstream.

By contrast, the sibling burn op `DelegateStxOp::check()` correctly returns an error for invalid `until_burn_height`: [3](#0-2) 

confirming that the intended pattern for this validation function is to reject the operation via `Err`, and that the `num_cycles` branch in `StackStxOp::check` is a broken/no-op guard rather than intentional lenient behavior.

### Impact Explanation
`num_cycles` is the `lock-period` value that flows from this burn operation into the `.pox-4`/`pox-locking` machinery, ultimately determining how long a stacker's STX is locked and which reward cycles the reward-set entry spans. If `check()` fails to actually enforce `0 < num_cycles <= POX_MAX_NUM_CYCLES`, any unprivileged Bitcoin-transaction sender can submit a `StackStxOp` with `num_cycles = 0` or `num_cycles` far in excess of `POX_MAX_NUM_CYCLES`. Depending on how downstream reward-cycle/unlock-height arithmetic handles this un-bounded value (e.g. `reward-cycle-to-burn-height (+ first-reward-cycle lock-period)` style computations seen in `pox-4.clar`), this can result in a stacker's STX being locked for an unintended/unbounded number of cycles (permanent or excessively long freezing of staked STX) or a `num_cycles = 0` op being treated as a valid stack with no real lock period, breaking the invariant that every accepted `stack-stx` burn op has a lock period within `(0, POX_MAX_NUM_CYCLES]`.

### Likelihood Explanation
Likelihood is low-to-moderate: this requires crafting a raw Bitcoin `OP_RETURN` payload (not going through the normal signer-authorization path used by `pox-4.clar`'s Clarity-level `stack-stx`), which is achievable by any unprivileged party who controls a Bitcoin transaction, but the actual damage depends on whether downstream cycle/height arithmetic in `pox-4.clar`/`pox-locking` independently re-validates `num_cycles`/`lock-period`, which could not be fully confirmed within the scope of this investigation.

### Recommendation
Fix `StackStxOp::check()` so the `num_cycles` branch returns an error, matching the pattern used for `stacked_ustx`:
```rust
if self.num_cycles == 0 || self.num_cycles > POX_MAX_NUM_CYCLES {
    warn!(...);
    return Err(op_error::StackStxInvalidCycles); // or equivalent
}
```

### Proof of Concept
1. Construct a Bitcoin transaction with `Opcodes::StackStx` opcode and payload bytes such that `data[16]` (the `num_cycles` byte) is `0` or `> POX_MAX_NUM_CYCLES`.
2. Submit it as the second leg of a valid `PreStxOp`/`StackStxOp` pair, satisfying `StackStxOp::parse_from_tx`'s other structural checks (matching opcode, valid outputs, valid `sender` linkage via `PreStxOp`).
3. `StackStxOp::check()` is called on the resulting op; because the `num_cycles` bounds-violation branch only warns and does not return `Err`, `check()` returns `Ok(())` and the operation is treated as valid, propagating the out-of-range `num_cycles` downstream as the stacking lock period. [2](#0-1)

### Citations

**File:** stackslib/src/chainstate/burn/operations/stack_stx.rs (L200-201)
```rust
        let stacked_ustx = parse_u128_from_be(data.get(0..16)?).unwrap();
        let num_cycles = *data.get(16)?;
```

**File:** stackslib/src/chainstate/burn/operations/stack_stx.rs (L398-419)
```rust
impl StackStxOp {
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

**File:** stackslib/src/chainstate/burn/operations/delegate_stx.rs (L207-225)
```rust
    pub fn check(&self) -> Result<(), op_error> {
        if self.delegated_ustx == 0 {
            warn!("Invalid DelegateStxOp, must have positive ustx");
            return Err(op_error::DelegateStxMustBePositive);
        }

        if let Some(height) = self.until_burn_height {
            if height > i64::MAX as u64 {
                warn!(
                    "Invalid DelegateStxOp: until_burn_height exceeds i64::MAX";
                    "until_burn_height" => height,
                    "txid" => %self.txid,
                );
                return Err(op_error::InvalidInput);
            }
        }

        Ok(())
    }
```
