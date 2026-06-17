### Title
Asymmetric `delta_gas` Adjustment in `compute_gas_refund` Causes User Overpayment - (`File: basic_bootloader/src/bootloader/transaction_flow/refund_calculation.rs`)

---

### Summary

`compute_gas_refund` adjusts `gas_used` upward when native resource consumption exceeds EVM gas consumption (`delta_gas > 0`), but never adjusts it downward when EVM gas consumption exceeds native resource consumption (`delta_gas < 0`). The code even contains a `// TODO: return delta_gas to gas_used?` comment acknowledging the missing symmetric case. The result is that users are overcharged: the excess fee is transferred to the operator (coinbase) instead of being refunded to the sender.

---

### Finding Description

In `compute_gas_refund`, the double-resource accounting reconciliation step computes:

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

`delta_gas` represents `(native_used / native_per_gas) - gas_used`:

- **`delta_gas > 0`**: native cost (in gas units) exceeds EVM gas used → `gas_used` is increased so the user pays for the native overhead. This is correct.
- **`delta_gas < 0`**: EVM gas used exceeds native cost (in gas units) → `gas_used` should be *decreased* so the user is refunded the difference. This branch is entirely absent. The `// TODO` comment explicitly flags this gap.

Because `gas_used` is not reduced when `delta_gas < 0`, the final refund calculation:

```rust
let total_gas_refund = gas_limit - gas_used;
``` [2](#0-1) 

produces a smaller refund than the user is entitled to. The shortfall is paid to the operator via:

```rust
let token_to_pay_operator = U256::from(context.gas_used)
    .checked_mul(gas_price_for_operator)
    ...
``` [3](#0-2) 

This is the direct analog of the M-03 Vault bug: just as `deposit.amount = 0` unconditionally zeroed the full deposit instead of reducing it by the used portion, here `gas_used` is only ever increased by `delta_gas`, never decreased — causing the "remaining" (refundable) amount to be systematically understated.

`compute_gas_refund` is called for both L2 transactions (via `before_refund` in `ZkTransactionFlowOnlyEOA`) and L1→L2 transactions: [4](#0-3) [5](#0-4) 

---

### Impact Explanation

When `delta_gas < 0` (EVM gas used > native cost in gas units), the user's `gas_used` is overstated. The refund `(gas_limit - gas_used) * gas_price` is smaller than it should be. The difference is silently transferred to the operator as excess fee. This is a direct, per-transaction financial loss for the sender, with no recovery path. The magnitude is `|delta_gas| * gas_price` tokens per affected transaction.

---

### Likelihood Explanation

`delta_gas < 0` occurs whenever a transaction's EVM gas consumption exceeds its native resource cost expressed in gas units: `gas_used > native_used / native_per_gas`. This is a realistic and common condition for transactions that execute many EVM opcodes but write little pubdata (e.g., pure computation, in-memory loops, read-heavy contracts). Any unprivileged L2 or L1→L2 transaction sender can trigger this path without any special privileges. The `// TODO` comment confirms the developers are aware the negative case is unhandled.

---

### Recommendation

Apply the symmetric adjustment: when `delta_gas < 0`, reduce `gas_used` by `|delta_gas|`, clamped to `minimal_gas_used` to avoid under-charging intrinsic costs:

```rust
if delta_gas > 0 {
    gas_used += delta_gas as u64;
} else if delta_gas < 0 {
    // Native cost is lower than EVM gas cost; refund the difference.
    let reduction = (-delta_gas) as u64;
    gas_used = gas_used.saturating_sub(reduction).max(minimal_gas_used);
}
```

Remove the `// TODO: return delta_gas to gas_used?` comment once addressed.

---

### Proof of Concept

1. User submits an L2 EIP-1559 transaction with `gas_limit = 100_000`, `gas_price = 1000`, `native_price = 1`, resulting in `native_per_gas = 1000`.
2. Transaction executes: EVM uses 80,000 gas (`gas_used = 80_000`); native resource consumed = 50,000,000 units → `native_used / native_per_gas = 50_000`.
3. `delta_gas = 50_000 - 80_000 = -30_000` (negative).
4. The `if delta_gas > 0` branch is skipped; `gas_used` stays at `80_000`.
5. Refund = `(100_000 - 80_000) * 1000 = 20_000_000` tokens.
6. Correct refund should be `(100_000 - 50_000) * 1000 = 50_000_000` tokens.
7. User loses `30_000_000` tokens; operator receives them instead.

The entry path is a standard unprivileged L2 transaction processed through `ZkTransactionFlowOnlyEOA::before_refund` → `compute_gas_refund`. [1](#0-0)

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

**File:** basic_bootloader/src/bootloader/transaction_flow/refund_calculation.rs (L83-83)
```rust
    let total_gas_refund = gas_limit - gas_used;
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

**File:** basic_bootloader/src/bootloader/transaction_flow/zk/mod.rs (L514-516)
```rust
        let token_to_pay_operator = U256::from(context.gas_used)
            .checked_mul(gas_price_for_operator)
            .ok_or(internal_error!("gu*gpfo"))?;
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
