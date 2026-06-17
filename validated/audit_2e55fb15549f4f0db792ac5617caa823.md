### Title
Asymmetric `delta_gas` Adjustment in `compute_gas_refund` Systematically Overcharges Users When Native Resource Consumption Is Below EVM Gas Consumption - (`File: basic_bootloader/src/bootloader/transaction_flow/refund_calculation.rs`)

---

### Summary

`compute_gas_refund` applies a `delta_gas` correction only in the positive direction: when native resource consumption exceeds EVM gas consumption, `gas_used` is increased and the user pays more. When native resource consumption is *below* EVM gas consumption (`delta_gas < 0`), `gas_used` is left unchanged and the user receives no refund for the unused native budget they pre-funded. The developer explicitly flagged this with `// TODO: return delta_gas to gas_used?` at line 80. The result is a systematic, protocol-level overcharge of users whose transactions are EVM-heavy but proving-light.

---

### Finding Description

ZKsync OS implements a double resource accounting model. For every transaction, the user pre-pays `gasLimit * gasPrice` tokens. A `nativePerGas` ratio is derived as `gasPrice / nativePrice`, and the user's native resource budget is set to `gasLimit * nativePerGas`. After execution, `compute_gas_refund` reconciles the two dimensions:

```
deltaGas := (nativeUsed / nativePerGas) - gasUsed
```

The documentation in `docs/double_resource_accounting.md` states: *"If `deltaGas > 0`, we add it to `gasUsed`"* — but it says nothing about the negative case. The code confirms this asymmetry:

```rust
// basic_bootloader/src/bootloader/transaction_flow/refund_calculation.rs, lines 69-80
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
```

When `delta_gas < 0` — meaning the transaction consumed fewer native resources than the EVM gas dimension implies — `gas_used` is not reduced. The user is refunded only `(gasLimit - gas_used) * gasPrice`, where `gas_used` is inflated relative to the actual native cost. The operator receives `gas_used * gas_price_for_operator` based on this inflated figure.

This path is reached for every successfully executed transaction through both the Ethereum-style flow (`ethereum/mod.rs::refund_and_commit_fee`) and the ZK-style flow (`zk/mod.rs::refund_and_commit_fee`), both of which consume the `gas_used` value produced by `compute_gas_refund`.

---

### Impact Explanation

**Vulnerability class**: Resource accounting bug — asymmetric fee adjustment with no refund path for unused native resources.

**Direct financial loss to users**: Any transaction where EVM gas consumption exceeds the native-resource-equivalent gas is overcharged. The overcharge per transaction is:

```
overcharge = |delta_gas| * gasPrice
           = (gasUsed - nativeUsed/nativePerGas) * gasPrice
```

For example, with `gasPrice = 1000`, `nativePrice = 10`, `nativePerGas = 100`:
- EVM gas used = 80,000 (from ergs)
- Native used = 4,000,000 (equivalent to 40,000 gas)
- `delta_gas = 40,000 - 80,000 = -40,000` → not applied
- User charged for 80,000 gas; actual native cost equivalent = 40,000 gas
- Overcharge = 40,000 × 1,000 = **40,000,000 tokens** (50% overcharge)

The excess is not burned — it flows to the operator as inflated `gas_used * gas_price_for_operator`. This creates a misaligned incentive: the operator benefits financially from transactions that are EVM-heavy but proving-light, with no mechanism to return the surplus to users.

---

### Likelihood Explanation

This condition (`delta_gas < 0`) is reached whenever a transaction performs EVM-heavy computation that is relatively cheap to prove. Common examples include:
- Transactions with large calldata that is read but not written to storage (high EVM gas for memory ops, low native for proving)
- Transactions that perform many arithmetic/comparison opcodes (EVM gas-intensive, but RISC-V cycle-light)
- Any transaction where the `nativePerGas` ratio is set low by the operator (low `nativePrice`), making native resources cheap relative to EVM gas

This is not an edge case — it is the normal operating condition for a large class of transactions. The `// TODO: return delta_gas to gas_used?` comment confirms the developers are aware this case is unhandled. Every such transaction silently overcharges the sender with no recourse.

---

### Recommendation

In `compute_gas_refund`, apply the `delta_gas` correction symmetrically. When `delta_gas < 0`, reduce `gas_used` by `|delta_gas|`, subject to the `minimal_gas_used` floor:

```rust
if delta_gas > 0 {
    gas_used += delta_gas as u64;
} else if delta_gas < 0 {
    let reduction = (-delta_gas) as u64;
    gas_used = gas_used.saturating_sub(reduction).max(minimal_gas_used);
}
```

This ensures users are charged only for the maximum of their EVM gas consumption and their native resource consumption (expressed in gas units), which is the symmetric and fair interpretation of the double resource accounting model described in `docs/double_resource_accounting.md`.

---

### Proof of Concept

**Root cause location**: `basic_bootloader/src/bootloader/transaction_flow/refund_calculation.rs`, lines 66–81.

**Step-by-step trace**:

1. User submits a transaction with `gasLimit = 100_000`, `gasPrice = 1000`, block `nativePrice = 10`.
2. `nativePerGas = ceil(1000 / 10) = 100` (computed in `zk/validation_impl.rs` line 135).
3. `nativeLimit = 100_000 * 100 = 10_000_000` (set in `gas_helpers.rs::create_resources_for_tx`).
4. Transaction executes; EVM consumes 80,000 gas (ergs = 80,000 × 256). Native consumed = 4,000,000 units.
5. `compute_gas_refund` is called:
   - `gas_used = gasLimit - remaining_ergs/ERGS_PER_GAS = 80,000`
   - `native_used = 10_000_000 - remaining_native = 4_000_000`
   - `delta_gas = (4_000_000 / 100) as i64 - 80_000 as i64 = 40_000 - 80_000 = -40_000`
   - `delta_gas < 0` → branch not taken, `gas_used` stays at 80,000
   - `// TODO: return delta_gas to gas_used?` — acknowledged but unresolved
6. `refund_and_commit_fee` (ZK path, `zk/mod.rs` line 458):
   - `token_to_refund = gas_price * (gasLimit - gas_used) = 1000 * 20_000 = 20_000_000`
   - `token_to_pay_operator = gas_used * gas_price_for_operator = 80_000 * 1000 = 80_000_000`
7. **Correct charge** (if `delta_gas` were applied): `40_000 * 1000 = 40_000_000`.
8. **Actual charge**: `80_000_000`. **Overcharge**: `40_000_000` tokens (100% excess above fair cost).

The user has no recourse — the refund is computed and finalized within the same block execution, with no appeal mechanism. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5)

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

**File:** docs/double_resource_accounting.md (L47-52)
```markdown
Then we compute the difference between the implicit gas used derived from native resource consumption and the gas used by EEs from the ergs used. We call this value `deltaGas`.
  `deltaGas := (nativeUsed / nativePerGas) - gasUsed`

If `deltaGas > 0`, we add it to `gasUsed` and charge it from ergs. This ensures that gas estimation will include additional gas to cover for native resources using just base fee. We expect the base fee to be enough to cover most transactions without the need of additional gas.

Finally, any remaining gas left is refunded as usual.
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

**File:** basic_bootloader/src/bootloader/transaction_flow/ethereum/mod.rs (L508-518)
```rust
        if context.tx_gas_limit > context.gas_used {
            system_log!(
                system,
                "Gas price for refund is {:?}\n",
                &context.tx_level_metadata.tx_gas_price
            );

            // refund
            let receiver = transaction.from();
            let refund = context.tx_level_metadata.tx_gas_price
                * U256::from(context.tx_gas_limit - context.gas_used); // can not overflow
```
