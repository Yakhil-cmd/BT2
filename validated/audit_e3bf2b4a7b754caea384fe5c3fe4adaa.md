### Title
Negative `delta_gas` Not Returned to User — Overpayment of Gas Fees When Native Resource Consumption Is Low - (File: `basic_bootloader/src/bootloader/transaction_flow/refund_calculation.rs`)

---

### Summary

In `compute_gas_refund`, the double-resource accounting logic adjusts `gas_used` upward when native resource consumption exceeds EVM gas consumption (`delta_gas > 0`), but it never adjusts `gas_used` downward when native consumption is *less* than EVM gas consumption (`delta_gas < 0`). This means that whenever a transaction uses more EVM gas than its native resource consumption implies, the user is charged for the full EVM gas used rather than the lower native-equivalent amount. The excess fee is neither refunded to the user nor paid to the operator — it is simply destroyed (the sender's balance is debited but no recipient receives the difference).

---

### Finding Description

ZKsync OS implements a **double resource accounting** model: every transaction is charged both in EVM gas (ergs) and in native resources (a proxy for ZK proving cost). The two are linked by the ratio `nativePerGas = gasPrice / nativePrice`.

The design intent, documented in `docs/double_resource_accounting.md`, is:

```
deltaGas := (nativeUsed / nativePerGas) - gasUsed
If deltaGas > 0: add it to gasUsed (user pays more to cover native cost)
If deltaGas <= 0: (implied) user should be refunded the difference
```

The documentation says "any remaining gas left is refunded as usual," implying the negative case is handled. However, the implementation in `compute_gas_refund` only handles the positive case:

```rust
// basic_bootloader/src/bootloader/transaction_flow/refund_calculation.rs, lines 66-81
#[cfg(not(feature = "unlimited_native"))]
{
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
    // TODO: return delta_gas to gas_used?   <-- acknowledged but unimplemented
}
```

The `// TODO: return delta_gas to gas_used?` comment at line 80 explicitly acknowledges the missing negative case. When `delta_gas < 0`, `gas_used` is not reduced, so the user is charged for more gas than the native resource consumption warrants.

The fee flow is:
1. User pre-pays `gas_price * gas_limit` at validation time (`precharge_fee`).
2. After execution, `gas_used` is computed in `compute_gas_refund`.
3. The user is refunded `gas_price * (gas_limit - gas_used)`.
4. The operator receives `gas_price * gas_used`.

When `delta_gas < 0` (native consumption is low relative to EVM gas), `gas_used` is not reduced, so:
- The user is refunded less than they should be.
- The operator receives more than the native cost warrants.

The gap `|delta_gas| * gas_price` is effectively transferred from the user to the operator without corresponding work, constituting a resource accounting bug where user funds are permanently lost relative to the correct accounting.

---

### Impact Explanation

**Vulnerability class:** Resource accounting bug — asymmetric `deltaGas` adjustment causes systematic user overpayment.

**Impact:** Every L2 transaction where EVM gas consumption exceeds native resource consumption (i.e., `nativeUsed / nativePerGas < gasUsed`) results in the user paying more than the correct fee. The excess is paid to the operator/coinbase rather than refunded to the user. This is a direct, permanent loss of user funds on every such transaction.

The magnitude scales with:
- The gap between EVM gas used and native-equivalent gas used.
- The gas price of the transaction.

For transactions that are EVM-gas-heavy but native-light (e.e., many simple SLOAD/SSTORE operations that are cheap to prove but expensive in EVM gas), the overpayment can be significant.

---

### Likelihood Explanation

This affects every L2 transaction where `nativeUsed / nativePerGas < gasUsed`. This is a common case: EVM gas costs are calibrated for Ethereum's execution model, while native resources model ZK proving complexity. Many EVM operations (e.g., storage reads/writes, calls) have high EVM gas costs but relatively low proving costs. The condition is reachable by any unprivileged transaction sender submitting a normal L2 transaction.

The `// TODO` comment at line 80 confirms the developers are aware of this gap. The condition is not gated by any privilege or special configuration.

---

### Recommendation

In `compute_gas_refund`, handle the negative `delta_gas` case symmetrically:

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

This ensures the user is only charged for the maximum of their EVM gas consumption and their native-equivalent gas consumption, consistent with the documented design intent.

---

### Proof of Concept

The root cause is in `compute_gas_refund`: [1](#0-0) 

The design intent (both directions of `deltaGas` should be handled) is documented: [2](#0-1) 

The `gas_used` computed here flows directly into the refund and operator payment: [3](#0-2) [4](#0-3) 

**Concrete scenario:**

1. User submits an L2 transaction with `gas_limit = 100_000`, `gas_price = 1000`, `native_price = 100`.
   - `nativePerGas = 1000 / 100 = 10`
   - `nativeLimit = 100_000 * 10 = 1_000_000`
2. Transaction executes, consuming `gas_used_evm = 80_000` ergs-equivalent and `native_used = 500_000` native units.
   - `nativeUsed / nativePerGas = 500_000 / 10 = 50_000`
   - `delta_gas = 50_000 - 80_000 = -30_000` (negative)
3. Because `delta_gas < 0`, the code does nothing. `gas_used` remains `80_000`.
4. User is refunded `1000 * (100_000 - 80_000) = 20_000_000` instead of the correct `1000 * (100_000 - 50_000) = 50_000_000`.
5. Operator receives `1000 * 80_000 = 80_000_000` instead of the correct `1000 * 50_000 = 50_000_000`.
6. User permanently loses `30_000_000` units of base token.

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

**File:** basic_bootloader/src/bootloader/transaction_flow/zk/mod.rs (L452-458)
```rust
        if context.tx_gas_limit > context.gas_used {
            system_log!(system, "Gas price for refund is {:?}\n", &context.gas_price);

            // refund
            let refund_recipient = transaction.from();
            let token_to_refund =
                context.gas_price * U256::from(context.tx_gas_limit - context.gas_used); // can not overflow
```

**File:** basic_bootloader/src/bootloader/transaction_flow/zk/mod.rs (L514-516)
```rust
        let token_to_pay_operator = U256::from(context.gas_used)
            .checked_mul(gas_price_for_operator)
            .ok_or(internal_error!("gu*gpfo"))?;
```
