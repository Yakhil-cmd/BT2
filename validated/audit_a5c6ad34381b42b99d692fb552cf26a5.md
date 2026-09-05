## Title
Missing Enforcement in `StackStxOp::check` Allows Out-of-Range `num_cycles` to Bypass Validation - (File: stackslib/src/chainstate/burn/operations/stack_stx.rs)

### Summary
`StackStxOp::check()` is supposed to reject a Bitcoin-broadcast `stack-stx` operation whose `num_cycles` field is `0` or greater than `POX_MAX_NUM_CYCLES`, but the offending branch only logs a warning and falls through to `Ok(())` — it never returns an error. This mirrors the reported bug class in `call` (a validation rule that looks like it constrains a parameter but never actually rejects the "empty"/out-of-range case), since the intended guard is syntactically present but has no enforcement effect.

### Finding Description
The check function is: [1](#0-0) 

```
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
``` [1](#0-0) 

The `stacked_ustx == 0` branch correctly `return`s an error, but the `num_cycles` branch only emits a `warn!` and does not return `Err(...)`, so execution always proceeds to the final `Ok(())`. This is a straightforward equality/validation bypass: the function's contract (as documented) is "reject num_cycles outside (0, POX_MAX_NUM_CYCLES]", but the actual behavior never enforces that for any input.

`num_cycles` is parsed directly from the raw burnchain (Bitcoin) transaction payload as an arbitrary `u8`: [2](#0-1) 

so an attacker fully controls this value simply by crafting the Bitcoin OP_RETURN payload for a `StackStxOp`.

### Impact Explanation
Whether this is exploitable end-to-end depends on whether a downstream consumer of `StackStxOp` (e.g., `collect_pox_4_stacking_args`/the PoX Clarity contract call in `stackslib/src/chainstate/stacks/db/blocks.rs`) re-validates `num_cycles`/`lock-period` before it reaches state that affects locking, rewards, or the reward-set weight. I was not able to fully trace, within the remaining iterations, whether the Clarity-side `check-pox-lock-period` (which independently enforces `1 <= lock-period <= 12`) is invoked on this exact value before it is used to compute `first-reward-cycle`/`lock-period` for a burnchain-originated stack-stx operation, or whether any burnchain-op-specific code path uses `num_cycles` (e.g., for cycle-count arithmetic, event/reporting logic, or reward-set entry construction) without going through `can-stack-stx`/`minimal-can-stack-stx`. If there exists any such path that trusts `StackStxOp::check()` as the sole gate on `num_cycles` and then uses it in arithmetic (e.g., `add-pox-partial-stacked`'s cycle-index fold, or reward-cycle math) without the contract-level range check, a `num_cycles == 0` value could produce degenerate/looping behavior or a reward-cycle assignment that does not correspond to any real cycle, and a `num_cycles` far above `POX_MAX_NUM_CYCLES` could inflate `lock-period` beyond intended bounds. Given the strong redundant validation in the Clarity contracts (`check-pox-lock-period`, `minimal-can-stack-stx`), the most defensible claim is a **defense-in-depth / validation-bypass bug at the burnchain-ops layer**, not a proven unbacked mint or permanent freeze — I could not confirm a concrete equality break (locked-vs-owed STX, or reward-slot-vs-stake) purely from the ops-layer bug without further tracing of `blocks.rs`'s consumption of `StackStxOp.num_cycles`.

### Likelihood Explanation
High likelihood of triggering the code path: any user can broadcast a Bitcoin transaction encoding a `StackStxOp` with `num_cycles = 0` or `num_cycles > 12`, and `check()` will accept it. Likelihood of a *severe* consensus-level impact is lower and unconfirmed, since it depends on whether Clarity-side redundant checks (`check-pox-lock-period`) are actually applied to this specific value in the burn-op consumption path — which I was unable to confirm with certainty in the available context.

### Recommendation
Fix `StackStxOp::check()` to actually reject invalid `num_cycles`:
```rust
if self.num_cycles == 0 || self.num_cycles > POX_MAX_NUM_CYCLES {
    warn!(...);
    return Err(op_error::StackStxInvalidCycles); // or equivalent
}
```
Additionally, audit `stackslib/src/chainstate/stacks/db/blocks.rs` (`collect_pox_4_stacking_args`/`process_stack_stx_ops`) to confirm that `num_cycles` from a burnchain-originated `StackStxOp` is always passed through the Clarity `can-stack-stx`/`minimal-can-stack-stx` range check before affecting locked amounts, reward-cycle assignment, or reward-set weight, and add regression tests asserting `StackStxOp::check()` returns `Err` for `num_cycles == 0` and `num_cycles > POX_MAX_NUM_CYCLES`.

### Proof of Concept
1. Craft a Bitcoin transaction with the `StackStxOp` opcode and payload where the `cycles` byte (offset 16 in the wire format, per the comment at [3](#0-2)  ) is `0x00`.
2. Broadcast it as the follow-up to a valid `PreStxOp` so `StackStxOp::from_tx`/`parse_from_tx` succeeds.
3. Observe that `StackStxOp::check()` logs a warning but returns `Ok(())`, i.e., the operation is not rejected at the burnchain-ops validation layer, confirming the missing `return Err(...)` at [4](#0-3) .

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
                "StacksStxOp payload is malformed ({} bytes, expected {} or more)",
                data.len(),
                17
            );
            return None;
        }

        let stacked_ustx = parse_u128_from_be(data.get(0..16)?).unwrap();
        let num_cycles = *data.get(16)?;

        let mut signer_key: Option<StacksPublicKeyBuffer> = None;
        let mut max_amount: Option<u128> = None;
        let mut auth_id: Option<u32> = None;

        if data.len() >= 50 {
            signer_key = Some(StacksPublicKeyBuffer::from(data.get(17..50)?));
        }
        if data.len() >= 66 {
            let Some(amt) = parse_u128_from_be(data.get(50..66)?) else {
                return None;
            };
            max_amount = Some(amt);
        }
        if data.len() >= 70 {
            let Some(id) = parse_u32_from_be(data.get(66..70)?) else {
                return None;
            };
            auth_id = Some(id);
        }

        Some(ParsedData {
            stacked_ustx,
            num_cycles,
            signer_key,
            max_amount,
            auth_id,
        })
    }
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
