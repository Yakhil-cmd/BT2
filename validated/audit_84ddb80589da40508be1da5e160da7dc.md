### Title
Pre-check Native Budget Underestimates Actual Native Charge Due to `mod_size` Rounding in `native_cost` — (`basic_system/src/system_functions/modexp/mod.rs`)

### Summary

`modexp_as_system_function_inner` performs a pre-check using `resources_from_ergs(MODEXP_MINIMAL_COST_ERGS)` (200 gas → 60,000 native) before parsing inputs. The subsequent actual charge calls `native_cost`, which internally re-runs `ergs_cost` with `mod_size.next_multiple_of(32)` instead of the real `mod_size`. For inputs where the real ergs cost hits the 200-gas floor but the rounded mod_size pushes the native-path gas above 200, the actual native charge exceeds 60,000 — causing the pre-check to pass while the actual `resources.charge(...)` returns OOG. On Ethereum mainnet the same call succeeds at exactly 200 gas.

---

### Finding Description

**Pre-check path** — `modexp_as_system_function_inner`, lines 118–121:

```rust
let minimal_resources = resources_from_ergs::<R>(MODEXP_MINIMAL_COST_ERGS);
if !resources.has_enough(&minimal_resources) {
    return Err(out_of_ergs_error!().into());
}
```

`resources_from_ergs` with `MODEXP_MINIMAL_COST_ERGS = Ergs(200 * ERGS_PER_GAS)`:

```
native_pre_check = (200 * ERGS_PER_GAS / ERGS_PER_GAS) * 300 = 60,000
``` [1](#0-0) 

**Actual charge path** — lines 191–193:

```rust
let ergs = ergs_cost(base_len as u64, exp_len as u64, mod_len as u64, &exp_highp)?;
let native = native_cost::<R>(base_len as u64, exp_len as u64, mod_len as u64, &exp_highp)?;
resources.charge(&R::from_ergs_and_native(ergs, native))?;
``` [2](#0-1) 

`native_cost` calls `ergs_cost` with `mod_size.next_multiple_of(32)`:

```rust
let ergs = ergs_cost(
    base_size,
    exp_size,
    mod_size.next_multiple_of(32),   // ← rounded up
    exp_highp,
)?;
``` [3](#0-2) 

The rounding can push the gas value above 200 even when the real `ergs_cost` returns exactly 200 (the EIP-2565 floor), producing a native charge > 60,000.

---

### Concrete Counterexample

Parameters: `base_len = 1`, `exp_len = 5`, `mod_len = 1`, `exp_highp = 2^38` (a 39-bit value, fits in 5 bytes).

**`ergs_cost(1, 5, 1, 2^38)` — used for the ergs charge:**
- `max_length = max(1,1) = 1`, `words = ⌈1/8⌉ = 1`, `mc = 1`
- `ic = bit_len(2^38) − 1 = 38`
- `computed_gas = 1 × 38 / 3 = 12`
- `gas = max(200, 12) = 200` ✓ (floor)

**`ergs_cost(1, 5, 32, 2^38)` — used inside `native_cost` (mod_len rounded to 32):**
- `max_length = max(1,32) = 32`, `words = ⌈32/8⌉ = 4`, `mc = 16`
- `ic = 38`
- `computed_gas = 16 × 38 / 3 = 202`
- `gas = max(200, 202) = 202`
- `native = 202 × 300 = 60,600`

**Result:**
- Pre-check native budget: **60,000**
- Actual native charge: **60,600**
- Discrepancy: **+600 native units**

A caller with exactly 200 EVM gas (native = 60,000) passes `has_enough` but then hits OOG at `resources.charge(...)`. [4](#0-3) [5](#0-4) 

---

### Impact Explanation

On Ethereum mainnet, any modexp call with EIP-2565 gas ≤ 200 succeeds at exactly 200 gas. On ZKsync OS, the same call with exactly 200 gas can revert with OOG after passing the pre-check, because the native charge is computed against a larger (rounded) modulus. This is a concrete EVM deviation: a contract that works on L1 with a tight gas budget for modexp will silently fail on ZKsync OS.

The `BaseResources::charge` implementation confirms both ergs and native are checked independently — a native shortfall causes a hard error even when ergs are sufficient: [6](#0-5) 

---

### Likelihood Explanation

The trigger requires:
1. `mod_len ∈ [1..31]` (so `next_multiple_of(32) = 32`, amplifying `max_length`)
2. `base_len` small enough that `max(base_len, mod_len) ≤ 8` (so actual `mc = 1`)
3. `exp_highp` large enough that `ic ≥ 38` (39-bit exponent, easily crafted in 5 bytes)
4. The caller's native budget is derived from exactly 200 gas at a `nativePerGas` ratio of 300

Conditions 1–3 are trivially crafted by any caller. Condition 4 depends on the `gasPrice / nativePrice` ratio equaling exactly 300 (`MODEXP_WORST_CASE_NATIVE_PER_GAS`), which is the design-time constant used for the pre-check. Any deployment where this ratio is at or near 300 is vulnerable.

---

### Recommendation

Replace the hard-coded `MODEXP_MINIMAL_COST_ERGS`-based pre-check native budget with one that accounts for the worst-case rounding applied in `native_cost`. The simplest fix is to compute the pre-check native using `mod_size = 32` (the smallest rounded value) when `mod_len < 32`, or to derive `minimal_resources` by calling `native_cost` with `mod_len = 0` rounded up (i.e., 32). Alternatively, the pre-check can be dropped entirely and the single `resources.charge(...)` at line 193 relied upon exclusively, since it already handles the OOG case correctly.

---

### Proof of Concept

```rust
// Encode: base_len=1, exp_len=5, mod_len=1
// exp = 0x4000000000 (2^38, 5 bytes), base = 0x02, modulus = 0x03
let mut input = vec![0u8; 96];
input[31] = 1;   // base_len = 1
input[63] = 5;   // exp_len = 5
input[95] = 1;   // mod_len = 1
input.push(0x02);                                   // base
input.extend_from_slice(&[0x40,0x00,0x00,0x00,0x00]); // exp = 2^38
input.push(0x03);                                   // modulus

// Provide exactly 200 EVM gas worth of resources
// (ergs = 200 * ERGS_PER_GAS, native = 200 * 300 = 60_000)
let ergs = Ergs(200 * ERGS_PER_GAS);
let native = DecreasingNative::from_computational(60_000u64);
let mut resources = BaseResources::from_ergs_and_native(ergs, native);

// Pre-check passes (has_enough returns true)
// Actual charge fails: native required = 60_600 > 60_000 available
let result = ModExpImpl::execute(&input, &mut vec![], &mut resources, ...);
assert!(result.is_err()); // OOG — but Ethereum would return Ok at 200 gas
```

### Citations

**File:** basic_system/src/system_functions/modexp/mod.rs (L80-87)
```rust
fn resources_from_ergs<R: Resources>(ergs: Ergs) -> R {
    let native = <R::Native as Computational>::from_computational(
        ergs.0
            .saturating_div(ERGS_PER_GAS)
            .saturating_mul(MODEXP_WORST_CASE_NATIVE_PER_GAS),
    );
    R::from_ergs_and_native(ergs, native)
}
```

**File:** basic_system/src/system_functions/modexp/mod.rs (L191-193)
```rust
    let ergs = ergs_cost(base_len as u64, exp_len as u64, mod_len as u64, &exp_highp)?;
    let native = native_cost::<R>(base_len as u64, exp_len as u64, mod_len as u64, &exp_highp)?;
    resources.charge(&R::from_ergs_and_native(ergs, native))?;
```

**File:** basic_system/src/system_functions/modexp/mod.rs (L289-294)
```rust
    let ergs = ergs_cost(
        base_size,
        exp_size,
        mod_size.next_multiple_of(32),
        exp_highp,
    )?;
```

**File:** basic_system/src/cost_constants.rs (L12-12)
```rust
pub const MODEXP_MINIMAL_COST_ERGS: Ergs = Ergs(200 * ERGS_PER_GAS);
```

**File:** basic_system/src/cost_constants.rs (L49-49)
```rust
pub const MODEXP_WORST_CASE_NATIVE_PER_GAS: u64 = 300;
```

**File:** zk_ee/src/reference_implementations/mod.rs (L100-110)
```rust
    fn charge(&mut self, to_charge: &Self) -> Result<(), SystemError> {
        if let Err(e) = self.ergs.charge(&to_charge.ergs) {
            // This method pre-charges for computation, both in ergs and native.
            // We first charge ergs, if they are insufficient, we do not charge
            // native, as the execution will halt with OOE and the computation
            // being charged for isn't performed.
            return Err(e);
        } else {
            self.native.charge(&to_charge.native)?
        };
        Ok(())
```
