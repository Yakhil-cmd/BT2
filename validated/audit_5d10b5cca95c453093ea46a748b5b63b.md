### Title
Wrapping Overflow in `fake_exponential` Produces Incorrect Blob Base Fee - (File: `basic_bootloader/src/bootloader/block_flow/ethereum/utils.rs`)

---

### Summary

The `fake_exponential` function used to compute the EIP-4844 blob base fee performs unchecked (wrapping) multiplication on `ruint::U256` values. For sufficiently large `excess_blob_gas` values supplied via oracle input, intermediate products silently overflow 256 bits, producing a cryptographically wrong blob base fee. This is a direct analog to the reported `priceX192 * 1e18` phantom-overflow pattern: a multiplication before a division where the intermediate value can exceed the word size.

---

### Finding Description

`fake_exponential` is called during Ethereum block header processing to derive `computed_blob_base_fee_per_gas`:

```rust
// basic_bootloader/src/bootloader/block_flow/ethereum/block_header.rs
let computed_blob_base_fee_per_gas = fake_exponential(
    U256::from(MIN_BASE_FEE_PER_BLOB_GAS),
    &U256::from(header.excess_blob_gas),
    &U256::from(BLOB_BASE_FEE_UPDATE_FRACTION),
);
```

The function itself:

```rust
// basic_bootloader/src/bootloader/block_flow/ethereum/utils.rs
pub(crate) fn fake_exponential(prefactor: U256, numerator: &U256, denominator: &U256) -> U256 {
    let mut i = 1;
    let mut output = U256::ZERO;
    let mut numerator_accumulator = prefactor * denominator;          // (A) unchecked mul
    while numerator_accumulator.is_zero() == false {
        output += &numerator_accumulator;                              // (B) unchecked add
        numerator_accumulator =
            (numerator_accumulator * numerator)                        // (C) unchecked mul — overflow here
            / (u256_mul_by_word(denominator, i).0);
        i += 1;
    }
    output / denominator
}
```

`ruint::Uint` implements `Mul` via `wrapping_mul`, meaning overflow is **always silent** (unlike Rust primitive integers which panic in debug mode). The developers themselves flagged this: the call site carries the comment `// TODO: consider if it's numerically stable over u64`.

**Overflow threshold analysis** — with `excess_blob_gas = x` and `denominator = BLOB_BASE_FEE_UPDATE_FRACTION = 5_007_716`:

| Iteration | `numerator_accumulator` (approx) |
|-----------|----------------------------------|
| 1 | `x` |
| 2 | `x² / (5e6 · 2)` |
| 3 | `x³ / (5e6² · 6)` |
| 5 | `≈ x⁵ / (5e6⁴ · 120)` |
| 6 (mul) | `≈ x⁶ / (5e6⁴ · 120)` — **overflows U256 when `x ≳ 2×10¹⁷`** |

`U256::MAX ≈ 1.16×10⁷⁷`. Solving `x⁶ > 1.16×10⁷⁷ · (5×10⁶)⁴ · 120` gives **`x ≳ 2×10¹⁷`**, well within the `u64` range (`u64::MAX ≈ 1.8×10¹⁹`). At that point, line (C) silently wraps, producing a garbage `numerator_accumulator` and therefore a garbage `computed_blob_base_fee_per_gas`.

The `output += &numerator_accumulator` at line (B) is also an unchecked wrapping addition that can overflow independently.

---

### Impact Explanation

`computed_blob_base_fee_per_gas` is stored and used to:
1. Validate that blob transactions pay at least the current blob base fee.
2. Charge blob fees during transaction processing.

A silently wrong (wrapped) blob base fee can be **arbitrarily small** (e.g., near zero), causing:
- Blob transactions to pass fee validation even when they underpay.
- Incorrect fee deduction from the sender, breaking the resource-accounting invariant.
- A **state-transition divergence** between ZKsync OS execution and the correct Ethereum state, which can invalidate the ZK proof or allow an incorrect proof to be accepted.

**Impact: High** — incorrect fee accounting and potential proof invalidity.

---

### Likelihood Explanation

`excess_blob_gas` is a `u64` field parsed from the Ethereum block header supplied by the oracle (prover). Under normal Ethereum protocol operation, `excess_blob_gas` grows by at most `393 216` per block, making values above `2×10¹⁷` unreachable in practice. However:

- The oracle data is provided by the **prover / forward execution input**, which the prompt explicitly lists as a valid attacker-controlled entry point.
- A prover supplying a crafted header with `excess_blob_gas ≥ 2×10¹⁷` (still a valid `u64`) triggers the overflow deterministically.

**Likelihood: Low** — requires a malicious or buggy prover to supply an out-of-range header field, but the code path is reachable and the overflow is deterministic once triggered.

---

### Recommendation

Replace the unchecked `*` operators with overflow-safe arithmetic. The standard approach (matching the reference `alloy` implementation) is to use widening multiplication and then divide:

```rust
// Instead of:
numerator_accumulator = (numerator_accumulator * numerator) / (u256_mul_by_word(denominator, i).0);

// Use widening mul (512-bit intermediate) then divide:
let (lo, hi) = numerator_accumulator.widening_mul(numerator); // produces U512
let divisor = u256_mul_by_word(denominator, i).0;
numerator_accumulator = wide_div_u256(lo, hi, divisor);       // divide 512-bit by 256-bit
```

Alternatively, saturate on overflow (since an astronomically large blob base fee is equivalent to "no blobs accepted"):

```rust
numerator_accumulator = numerator_accumulator
    .checked_mul(numerator)
    .map(|v| v / u256_mul_by_word(denominator, i).0)
    .unwrap_or(U256::ZERO); // saturate: loop terminates
```

The `output += &numerator_accumulator` addition should similarly use `saturating_add`.

---

### Proof of Concept

```
fake_exponential(
    U256::from(1u64),
    &U256::from(200_000_000_000_000_000u64),  // 2×10¹⁷, within u64
    &U256::from(5_007_716u64),
)
```

At iteration 6, `numerator_accumulator * numerator` exceeds `U256::MAX`. The `*` operator wraps silently, producing a value near zero. The loop terminates prematurely and `output / denominator` returns a blob base fee orders of magnitude below the correct value.

---

**Root cause file:** [1](#0-0) 

**Call site:** [2](#0-1) 

**Developer's own numerical-stability note:** [3](#0-2)

### Citations

**File:** basic_bootloader/src/bootloader/block_flow/ethereum/utils.rs (L4-15)
```rust
pub(crate) fn fake_exponential(prefactor: U256, numerator: &U256, denominator: &U256) -> U256 {
    let mut i = 1;
    let mut output = U256::ZERO;
    let mut numerator_accumulator = prefactor * denominator;
    while numerator_accumulator.is_zero() == false {
        output += &numerator_accumulator;
        numerator_accumulator =
            (numerator_accumulator * numerator) / (u256_mul_by_word(denominator, i).0);
        i += 1;
    }

    output / denominator
```

**File:** basic_bootloader/src/bootloader/block_flow/ethereum/block_header.rs (L215-220)
```rust
        // TODO: consider if it's numerically stable over u64
        let computed_blob_base_fee_per_gas = fake_exponential(
            U256::from(MIN_BASE_FEE_PER_BLOB_GAS),
            &U256::from(header.excess_blob_gas),
            &U256::from(BLOB_BASE_FEE_UPDATE_FRACTION),
        );
```
