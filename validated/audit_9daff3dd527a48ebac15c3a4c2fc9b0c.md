### Title
`StackStxOp::check()` never rejects invalid `num_cycles` (missing `return Err`) - (File: `stackslib/src/chainstate/burn/operations/stack_stx.rs`)

### Summary
`StackStxOp::check()` is supposed to enforce that a Bitcoin-broadcast `stack-stx` burnchain operation specifies a `num_cycles` value inside the valid range `(0, POX_MAX_NUM_CYCLES]`, mirroring the same bound that `pox-*.clar`'s `check-pox-lock-period` enforces at the Clarity layer. The Rust-side check only logs a warning on an out-of-range value and always returns `Ok(())`, so the op-level validation is a complete no-op.

### Finding Description
`StackStxOp::check` is implemented as: [1](#0-0) 

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
        ...
        Ok(())
    }
}
```

The `stacked_ustx == 0` branch correctly returns an error (`op_error::StackStxMustBePositive`). The `num_cycles` branch, by contrast, only calls `warn!(...)` and falls through — there is no `return Err(...)`. As a result, `check()` unconditionally returns `Ok(())` no matter what `num_cycles` is, including `0` (an instantly-expired/zero-length lock) or any value up to `u8::MAX` (255), far beyond the intended `POX_MAX_NUM_CYCLES` cap that every PoX Clarity contract (`pox.clar` through `pox-5.clar`) otherwise enforces via `check-pox-lock-period`/`MAX_POX_REWARD_CYCLES` (12) or `pox-5`'s `MAX_NUM_CYCLES` (96).

This is the exact bug class described in the external report: a duration/period bound exists in the code but is not actually enforced due to a broken control-flow path (in the ENS report, an unchecked cast; here, a missing `return`), letting a value outside the designed bound flow further into the system unchecked. `num_cycles` is attacker-controlled data parsed directly from an unprivileged Bitcoin transaction's OP_RETURN payload (see `parse_data`), so any user can broadcast a `StackStxOp` with `num_cycles = 0` or `num_cycles = 255` and have it pass `check()`. [2](#0-1) 

### Impact Explanation
Because `check()` is the op-level gate before a `StackStxOp` is admitted for further processing, this defeats the intended defense-in-depth boundary between the untrusted burnchain-operation layer and the Clarity contract layer. Depending on how downstream consumers of this op rely on `check()` having validated `num_cycles` (rather than re-deriving/re-validating it independently), a `num_cycles` of `0` or of an out-of-bounds large value can propagate into lock-period/unlock-height computations that assume the value is already sanitized, producing an incorrectly short (immediate unlock — value effectively never locked as intended) or incorrectly long (funds frozen far beyond the protocol's stated maximum lock period) stacking commitment. This falls into the "unlocking value never locked" / "temporary or permanent freezing of staked funds" impact category described in scope.

### Likelihood Explanation
High likelihood of reachability: any unprivileged party can construct and broadcast a Bitcoin transaction encoding a `StackStxOp` with an out-of-range `num_cycles` byte, since the field is a raw single byte read directly from transaction data with no signature or validation tying it to a sane range before `check()` runs, and `check()` itself does nothing to stop it.

### Recommendation
Add the missing `return Err(op_error::StackStxInvalidCycles)` (or an equivalent existing error variant) after the `warn!` in the `num_cycles` branch of `StackStxOp::check()`, matching the pattern already used for `stacked_ustx == 0`.

### Proof of Concept
1. Construct a `StackStxOp` (either directly in Rust or by encoding the corresponding Bitcoin `OP_RETURN` payload) with `num_cycles = 0` or `num_cycles = 200` (i.e., `> POX_MAX_NUM_CYCLES`).
2. Call `op.check()`.
3. Observe that the call returns `Ok(())` despite the invalid `num_cycles`, confirmed by tracing the code path: the `if self.num_cycles == 0 || self.num_cycles > POX_MAX_NUM_CYCLES` branch only executes `warn!(...)` and has no `return`, so execution always falls through to `Ok(())` at the end of the function. [3](#0-2)

### Citations

**File:** stackslib/src/chainstate/burn/operations/stack_stx.rs (L199-201)
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
