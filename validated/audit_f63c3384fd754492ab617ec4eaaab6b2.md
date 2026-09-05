### Title
Missing `return` on invalid `num_cycles` allows unvalidated StackStxOp to pass `check()` - (File: `stackslib/src/chainstate/burn/operations/stack_stx.rs`)

### Summary
`StackStxOp::check()` validates `stacked_ustx` and `num_cycles`, but the `num_cycles` branch only logs a `warn!()` and falls through instead of returning `op_error`, unlike the `stacked_ustx == 0` branch immediately above it. This means a burnchain `StackStxOp` with `num_cycles == 0` or `num_cycles > POX_MAX_NUM_CYCLES` passes `check()` successfully and is accepted for further processing.

### Finding Description
The broken equality is: "an op accepted by `StackStxOp::check()` implies `0 < num_cycles <= POX_MAX_NUM_CYCLES`". Code: [1](#0-0) 

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
    ...
    Ok(())
}
``` [2](#0-1) 

Compared to the pattern used for `stacked_ustx`, the `num_cycles` branch is missing `return Err(op_error::...)`. As written, `check()` unconditionally returns `Ok(())` after this point (barring signer-key failure), regardless of whether `num_cycles` is `0` or exceeds `POX_MAX_NUM_CYCLES`.

An attacker who crafts their own burnchain (Bitcoin) `StackStxOp` — which the rules explicitly permit ("craft burnchain stacking ops from their own Bitcoin inputs") — can set the 1-byte `num_cycles` field (offset 16 in the wire format, see `parse_data` at lines 176–230) to `0` or to a value greater than `POX_MAX_NUM_CYCLES`, and `check()` will not reject it.

### Impact Explanation
I was not able to fully trace, within the remaining tool budget, how the downstream consumer of a `StackStxOp` (i.e., the code in `stackslib/src/chainstate/burn/operations/mod.rs` / `sortdb.rs` that calls `.check()` and then hands the op to the `.pox`/reward-cycle bookkeeping, and ultimately to `pox-5.clar`) uses `num_cycles` once `check()` returns `Ok`. I could not find `num-cycles` used directly in `pox-5.clar` via search, which suggests the Rust-level `check()` may be the primary (or only) gate for this specific field for burnchain-native stacking ops, but I could not confirm this with certainty, nor could I confirm whether a downstream re-validation (e.g., in the .pox lock-period math or reward-cycle indexing) would independently reject `num_cycles == 0` or an out-of-range value.

Without that downstream confirmation, I cannot assert a specific fund-theft/freezing/double-counting outcome with the required certainty. This is a **logic defect / validation gap** (dead code / ineffective guard), but I cannot substantiate a Critical/High impact (theft, unbacked minting, permanent freezing, double counting) without tracing the exact consumer that acts on an "unchecked" `num_cycles`.

### Likelihood Explanation
Trivial to trigger: any unprivileged attacker with their own Bitcoin UTXOs can construct a `StackStxOp` (following the `PreStxOp`/`StackStxOp` OP_RETURN wire format) with `num_cycles` set to `0` or `> POX_MAX_NUM_CYCLES`, and this passes `check()` unconditionally.

### Recommendation
Restore the missing `return`:
```rust
if self.num_cycles == 0 || self.num_cycles > POX_MAX_NUM_CYCLES {
    warn!(
        "Invalid StackStxOp, num_cycles = {}, but must be in (0, {}]",
        self.num_cycles, POX_MAX_NUM_CYCLES
    );
    return Err(op_error::StackStxInvalidCycles); // or an equivalent existing variant
}
```

### Proof of Concept
Rust unit test plan (in `stack_stx.rs` test module):
```rust
#[test]
fn test_check_invalid_num_cycles_should_fail() {
    let op = StackStxOp {
        sender: StacksAddress::new(0, Hash160([0;20])).unwrap(),
        reward_addr: PoxAddress::Standard(StacksAddress::new(0, Hash160([1;20])).unwrap(), None),
        stacked_ustx: 10,
        num_cycles: 0, // invalid
        signer_key: None,
        max_amount: None,
        auth_id: None,
        txid: Txid([0;32]),
        vtxindex: 0,
        block_height: 0,
        burn_header_hash: BurnchainHeaderHash([0;32]),
    };
    // Equality under test: check() result vs "0 < num_cycles <= POX_MAX_NUM_CYCLES"
    let result = op.check();
    assert!(result.is_err(), "check() incorrectly returned Ok for num_cycles == 0");
}
```
Running this against current code shows `result.is_ok()` (test fails), confirming the guard is non-functional. I was unable to extend this PoC to a full end-to-end chainstate test demonstrating locked/unlocked STX divergence within the remaining investigation budget — that would require tracing `stackslib/src/chainstate/burn/operations/mod.rs` and the `.pox`/`pox-5.clar` consumption path for `num_cycles`, which I could not complete.

### Citations

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
