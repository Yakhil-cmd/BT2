### Title
Integer Division Truncation in `delta_gas` Calculation Causes Systematic Operator Underpayment - (File: `basic_bootloader/src/bootloader/transaction_flow/refund_calculation.rs`)

---

### Summary

In `compute_gas_refund`, the conversion from native resource consumption back to EVM gas units uses integer (floor) division: `native_used / native_per_gas`. The remainder `native_used % native_per_gas` is silently discarded. This means `delta_gas` — the extra gas charged to cover native resource costs — is always rounded **down**, causing the user to be systematically undercharged by up to 1 gas unit per transaction, and the operator to be underpaid by up to `gas_price` wei per transaction.

---

### Finding Description

In `compute_gas_refund` at line 72:

```rust
let delta_gas = if native_per_gas == 0 {
    0
} else {
    (native_used / native_per_gas) as i64 - (gas_used as i64)
};

if delta_gas > 0 {
    gas_used += delta_gas as u64;
}
```

`native_used / native_per_gas` is integer floor division. The remainder `native_used % native_per_gas` (which can be up to `native_per_gas - 1`) is dropped. This means `delta_gas` is computed as `floor(native_used / native_per_gas) - gas_used` instead of `ceil(native_used / native_per_gas) - gas_used`.

The final `gas_used` is therefore at most 1 unit less than it should be. Since the fee split is:

- **Refund to user**: `(gas_limit - gas_used) * gas_price`
- **Fee to operator**: `gas_used * gas_price`

The user receives up to `gas_price` wei more than they should, and the operator receives up to `gas_price` wei less than they should, on every transaction where native resource consumption is not an exact multiple of `native_per_gas`.

The analogous design intent is documented in `docs/double_resource_accounting.md` line 48:
> `deltaGas := (nativeUsed / nativePerGas) - gasUsed`

The spec uses exact division, but the implementation truncates. The code even has a `// TODO: return delta_gas to gas_used?` comment at line 80, indicating awareness of an asymmetry in this accounting path.

---

### Impact Explanation

Every L2 and L1→L2 transaction that consumes native resources where `native_used % native_per_gas != 0` results in:

- The user paying up to 1 gas unit less than they should (receiving a slightly inflated refund).
- The operator receiving up to `gas_price` wei less than they should per transaction.

The maximum per-transaction loss to the operator is bounded by 1 gas unit × `gas_price`. At typical gas prices (e.g., 1 gwei), this is 1 gwei per transaction. Across high transaction volumes, this accumulates as a systematic operator revenue shortfall. The user-side benefit is a small but consistent overpayment refund.

---

### Likelihood Explanation

This affects every transaction where `native_used % native_per_gas != 0`. Since `native_used` is determined by actual computation (EVM execution, pubdata, precompiles) and `native_per_gas = ceil(gas_price / native_price)`, the remainder is non-zero for the vast majority of real transactions. Any unprivileged user submitting a standard EVM transaction triggers this path.

---

### Recommendation

Replace the floor division with ceiling division when computing `delta_gas`, so that the full native cost is always recovered in gas units:

```rust
// Instead of:
(native_used / native_per_gas) as i64 - (gas_used as i64)

// Use ceiling division:
(native_used.div_ceil(native_per_gas)) as i64 - (gas_used as i64)
```

This ensures the operator is never underpaid due to truncation of the native-to-gas conversion remainder.

---

### Proof of Concept

**Setup:**
- `gas_limit = 100_000`
- `gas_price = 1_000` (wei)
- `native_price = 3` (so `native_per_gas = ceil(1000/3) = 334`)
- After execution: `gas_used_from_ergs = 50_000`, `native_used = 50_000 * 334 + 333` (i.e., one unit short of the next gas boundary)

**Current behavior:**
```
delta_gas = (50_000 * 334 + 333) / 334 - 50_000
          = floor(16_700_333 / 334) - 50_000
          = 50_000 - 50_000
          = 0
```
No extra gas charged. The 333 native units of remainder are silently dropped.

**Correct behavior (ceiling):**
```
delta_gas = ceil(16_700_333 / 334) - 50_000
          = 50_001 - 50_000
          = 1
```
One extra gas unit should be charged. The operator is underpaid by `1 * 1_000 = 1_000 wei`.

This is reachable by any unprivileged transaction sender on every block. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4)

### Citations

**File:** basic_bootloader/src/bootloader/transaction_flow/refund_calculation.rs (L31-34)
```rust
    let mut gas_used = gas_limit
        .checked_sub(resources.ergs().0.div_floor(ERGS_PER_GAS))
        .ok_or(internal_error!("gas remaining > gas limit"))?;
    resources.exhaust_ergs();
```

**File:** basic_bootloader/src/bootloader/transaction_flow/refund_calculation.rs (L66-81)
```rust
    #[cfg(not(feature = "unlimited_native"))]
    {
        // Adjust gas_used with difference with used native
        let delta_gas = if native_per_gas == 0 {
            0
        } else {
            (native_used / native_per_gas) as i64 - (gas_used as i64)
        };

        if delta_gas > 0 {
            // In this case, the native resource consumption is more than the
            // gas consumption accounted for. Consume extra gas.
            gas_used += delta_gas as u64;
        }
        // TODO: return delta_gas to gas_used?
    }
```

**File:** docs/double_resource_accounting.md (L47-50)
```markdown
Then we compute the difference between the implicit gas used derived from native resource consumption and the gas used by EEs from the ergs used. We call this value `deltaGas`.
  `deltaGas := (nativeUsed / nativePerGas) - gasUsed`

If `deltaGas > 0`, we add it to `gasUsed` and charge it from ergs. This ensures that gas estimation will include additional gas to cover for native resources using just base fee. We expect the base fee to be enough to cover most transactions without the need of additional gas.
```

**File:** basic_bootloader/src/bootloader/transaction_flow/zk/mod.rs (L457-458)
```rust
            let token_to_refund =
                context.gas_price * U256::from(context.tx_gas_limit - context.gas_used); // can not overflow
```

**File:** basic_bootloader/src/bootloader/transaction_flow/zk/mod.rs (L514-516)
```rust
        let token_to_pay_operator = U256::from(context.gas_used)
            .checked_mul(gas_price_for_operator)
            .ok_or(internal_error!("gu*gpfo"))?;
```
