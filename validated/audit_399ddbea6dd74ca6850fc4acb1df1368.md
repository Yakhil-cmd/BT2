### Title
One-Directional `delta_gas` Adjustment Causes Users to Overpay Gas Fees - (`basic_bootloader/src/bootloader/transaction_flow/refund_calculation.rs`)

---

### Summary

In `compute_gas_refund`, the ZKsync OS double-resource accounting model adjusts `gas_used` upward when native resource consumption exceeds EVM gas consumption, but never adjusts it downward when EVM gas consumption exceeds native resource consumption. This causes users to be overcharged for gas in the latter case, receiving a smaller refund than they are entitled to.

---

### Finding Description

ZKsync OS tracks two independent resources per transaction: **Ergs** (EVM gas equivalent) and **Native** (proving/RISC-V cycle cost). At the end of execution, `compute_gas_refund` reconciles the two via a `delta_gas` calculation:

```rust
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
``` [1](#0-0) 

The formula is:

```
delta_gas = (native_used / native_per_gas) - gas_used
```

- If `delta_gas > 0`: native consumption implies more gas was used than EVM tracking shows → `gas_used` is increased (user pays more).
- If `delta_gas < 0`: native consumption implies **less** gas was used than EVM tracking shows → `gas_used` is **not** decreased. The `TODO` comment explicitly acknowledges this gap.

The design documentation confirms the asymmetry is present:

> If `deltaGas > 0`, we add it to `gasUsed` and charge it from ergs. This ensures that gas estimation will include additional gas to cover for native resources using just base fee. [2](#0-1) 

No corresponding downward correction is described or implemented. The `TODO` comment at line 80 is the only acknowledgment that this case exists.

The resulting `gas_used` is then used to compute the user refund:

```rust
let refund = context.gas_price * U256::from(context.tx_gas_limit - context.gas_used);
``` [3](#0-2) 

Because `gas_used` is not reduced when `delta_gas < 0`, the refund is smaller than it should be.

`compute_gas_refund` is called from both the ZK L2 transaction path and the L1 transaction path: [4](#0-3) [5](#0-4) 

---

### Impact Explanation

Users are overcharged by `|delta_gas| * gas_price` per transaction whenever EVM gas consumption exceeds native resource consumption (in gas-equivalent terms). For a transaction consuming 1,000,000 EVM gas but only 500,000 native-equivalent gas, the user overpays by 500,000 × gas_price. At scale across many transactions, this represents a systematic, non-trivial financial loss to users. The overcharge is bounded by the transaction gas limit but is not negligible.

---

### Likelihood Explanation

The condition `delta_gas < 0` is triggered whenever a transaction's EVM gas consumption exceeds its native resource consumption in gas-equivalent terms. This is common for transactions with many arithmetic/logic EVM opcodes (high EVM gas, low proving cost) or transactions that use precompiles with fixed EVM gas costs but variable native costs. Any ordinary user submitting such a transaction is affected without any special setup.

---

### Recommendation

Implement the downward adjustment when `delta_gas < 0`, as the `TODO` comment already suggests:

```rust
if delta_gas > 0 {
    gas_used += delta_gas as u64;
} else if delta_gas < 0 {
    // Native consumption is less than EVM gas consumption.
    // Reduce gas_used so the user is refunded the difference.
    gas_used = gas_used.saturating_sub((-delta_gas) as u64);
    // Ensure gas_used does not fall below minimal_gas_used (already applied above).
    gas_used = core::cmp::max(gas_used, minimal_gas_used);
}
```

This mirrors the fix recommended in the GMX report: correct the accounting so the measured resource consumption accurately reflects what was actually consumed, and refund the remainder to the user.

---

### Proof of Concept

1. User submits a transaction with `gas_limit = 1_000_000`, `gas_price = 1000`, `native_price = 100`.
2. `native_per_gas = gas_price / native_price = 10`.
3. Transaction executes: EVM consumes 800,000 gas (`gas_used = 800_000`); native consumes 5,000,000 units (`native_used = 5_000_000`).
4. `native_used / native_per_gas = 500_000`.
5. `delta_gas = 500_000 - 800_000 = -300_000` (negative).
6. Current code: `delta_gas < 0`, so `gas_used` stays at `800_000`.
7. User refund: `(1_000_000 - 800_000) * 1000 = 200_000_000` units.
8. Correct behavior: `gas_used` should be reduced to `500_000`; refund should be `(1_000_000 - 500_000) * 1000 = 500_000_000` units.
9. User is overcharged by `300_000 * 1000 = 300_000_000` units.

### Citations

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

**File:** docs/double_resource_accounting.md (L47-51)
```markdown
Then we compute the difference between the implicit gas used derived from native resource consumption and the gas used by EEs from the ergs used. We call this value `deltaGas`.
  `deltaGas := (nativeUsed / nativePerGas) - gasUsed`

If `deltaGas > 0`, we add it to `gasUsed` and charge it from ergs. This ensures that gas estimation will include additional gas to cover for native resources using just base fee. We expect the base fee to be enough to cover most transactions without the need of additional gas.

```

**File:** basic_bootloader/src/bootloader/transaction_flow/zk/mod.rs (L427-434)
```rust
        let refund_info = compute_gas_refund(
            system,
            to_charge_for_pubdata,
            transaction.gas_limit(),
            min_gas_used,
            context.native_per_gas,
            &mut context.resources.main_resources,
        )?;
```

**File:** basic_bootloader/src/bootloader/transaction_flow/zk/mod.rs (L457-458)
```rust
            let token_to_refund =
                context.gas_price * U256::from(context.tx_gas_limit - context.gas_used); // can not overflow
```

**File:** basic_bootloader/src/bootloader/transaction_flow/zk/process_l1_transaction.rs (L262-273)
```rust
    let RefundInfo {
        gas_used,
        evm_refund,
        native_used,
    } = compute_gas_refund(
        system,
        to_charge_for_pubdata,
        gas_limit,
        minimal_gas_used,
        native_per_gas,
        &mut resources,
    )?;
```
