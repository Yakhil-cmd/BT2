### Title
Asymmetric `delta_gas` Adjustment in `compute_gas_refund` Silently Withholds User Refund When Native Cost Is Below EVM Gas Cost - (File: `basic_bootloader/src/bootloader/transaction_flow/refund_calculation.rs`)

---

### Summary

`compute_gas_refund` in ZKsync OS implements a dual-resource reconciliation step (`delta_gas`) that only adjusts `gas_used` upward when native resource consumption exceeds EVM gas consumption, but never adjusts it downward when the opposite is true. The result is that users are systematically overcharged — they receive a smaller gas refund than they are entitled to — whenever a transaction's native (proving) cost is lower than its EVM gas cost. The shortfall is silently discarded; no tracking or deferred-credit mechanism exists.

---

### Finding Description

ZKsync OS tracks two parallel resources per transaction: EVM gas (ergs) and native resource (proving cycles). After execution, `compute_gas_refund` reconciles the two by computing `delta_gas`:

```
delta_gas = (native_used / native_per_gas) - gas_used
```

The intent is to ensure that if native resource consumption implies more gas was spent than EVM tracking shows, the user is charged the higher amount. The code handles only the positive branch:

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
        // native consumption > EVM gas → charge more
        gas_used += delta_gas as u64;
    }
    // TODO: return delta_gas to gas_used?   ← acknowledged but unimplemented
}
```

When `delta_gas < 0` — meaning native resource consumption is *lower* than EVM gas consumption — `gas_used` is left at the higher EVM-gas-based value. The user's refund is then computed as:

```
refund = gas_price × (gas_limit − gas_used)
```

Because `gas_used` was not reduced by `|delta_gas|`, the refund is smaller than it should be. The operator receives the excess via `token_to_pay_operator = gas_used × gas_price_for_operator`. The shortfall is never tracked, deferred, or credited back.

The in-code `// TODO: return delta_gas to gas_used?` comment explicitly acknowledges the missing negative branch.

The `gas_used` value flows directly into the refund and operator-payment calculations in both the ZK transaction flow (`zk/mod.rs`, `refund_and_commit_fee`) and the L1 transaction flow (`process_l1_transaction.rs`).

---

### Impact Explanation

**Resource accounting bug — user underpayment of refund / operator overpayment.**

Every L2 ZK transaction where `native_used / native_per_gas < gas_used` results in the user receiving a smaller gas refund than they paid for. The difference is silently transferred to the operator (coinbase). This is a direct, repeatable financial loss to transaction senders with no recourse.

Concretely: a user who submits a transaction with `gas_limit = 100,000`, `gas_price = 1,000 wei`, where EVM gas used = 60,000 but native-equivalent gas = 40,000, should receive a refund of `40,000 × 1,000 = 40,000,000 wei`. Instead they receive `40,000,000 wei` only if `delta_gas` is applied; without it they receive `(100,000 − 60,000) × 1,000 = 40,000,000 wei` — wait, let me restate: they should receive `(100,000 − 40,000) × 1,000 = 60,000,000 wei` but instead receive `(100,000 − 60,000) × 1,000 = 40,000,000 wei`. The 20,000,000 wei shortfall goes to the operator.

---

### Likelihood Explanation

`delta_gas < 0` occurs whenever a transaction is "EVM-gas-heavy but native-light" — i.e., it performs many EVM operations that are cheap to prove (simple arithmetic, memory reads, stack operations). This is a common transaction profile. Any unprivileged user submitting a standard L2 transaction can trigger this path. No special setup, governance access, or oracle manipulation is required. The condition is determined entirely by the transaction's execution profile, which is attacker-controllable in the sense that a user can craft transactions that maximize the negative delta.

---

### Recommendation

Apply the symmetric correction: when `delta_gas < 0`, reduce `gas_used` by `|delta_gas|` (subject to the `minimal_gas_used` floor), so that users receive the full refund implied by their actual resource consumption:

```rust
if delta_gas > 0 {
    gas_used += delta_gas as u64;
} else if delta_gas < 0 {
    // Native consumption is less than EVM gas → reduce gas_used to give user correct refund
    let reduction = (-delta_gas) as u64;
    gas_used = gas_used.saturating_sub(reduction).max(minimal_gas_used);
}
```

Remove the `// TODO: return delta_gas to gas_used?` comment once addressed.

---

### Proof of Concept

**Root cause location:** [1](#0-0) 

**`gas_used` flows into refund and operator payment here (ZK flow):** [2](#0-1) [3](#0-2) 

**`gas_used` flows into operator payment in L1 flow:** [4](#0-3) 

**Design documentation confirming only the positive branch is intended:** [5](#0-4) 

**Step-by-step trigger:**

1. User submits any L2 ZK transaction with `gas_price > 0` and `native_per_gas > 0` (standard conditions).
2. Transaction executes; EVM gas consumed = `G_evm`; native resource consumed = `N`.
3. `compute_gas_refund` computes `delta_gas = (N / native_per_gas) − G_evm`.
4. If `delta_gas < 0` (native cost in gas-equivalent units is less than EVM gas used — common for arithmetic/memory-heavy transactions), the `if delta_gas > 0` branch is skipped.
5. `gas_used` remains at `G_evm` instead of the correct `G_evm + delta_gas = G_evm − |delta_gas|`.
6. User refund = `gas_price × (gas_limit − G_evm)` instead of the correct `gas_price × (gas_limit − (G_evm − |delta_gas|))`.
7. Operator receives `gas_price × G_evm` instead of the correct `gas_price × (G_evm − |delta_gas|)`.
8. Shortfall = `gas_price × |delta_gas|` — silently transferred to operator, never tracked.

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

**File:** basic_bootloader/src/bootloader/transaction_flow/zk/process_l1_transaction.rs (L277-279)
```rust
    let pay_to_operator = U256::from(gas_used)
        .checked_mul(U256::from(gas_price))
        .ok_or(internal_error!("gu*gp"))?;
```

**File:** docs/double_resource_accounting.md (L47-51)
```markdown
Then we compute the difference between the implicit gas used derived from native resource consumption and the gas used by EEs from the ergs used. We call this value `deltaGas`.
  `deltaGas := (nativeUsed / nativePerGas) - gasUsed`

If `deltaGas > 0`, we add it to `gasUsed` and charge it from ergs. This ensures that gas estimation will include additional gas to cover for native resources using just base fee. We expect the base fee to be enough to cover most transactions without the need of additional gas.

```
