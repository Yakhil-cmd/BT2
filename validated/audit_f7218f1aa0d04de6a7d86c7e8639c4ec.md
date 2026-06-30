### Title
EVM Executor Receives Full `transaction.gas_limit` Budget While Sender Pays Only `fixed_gas * price` in Silo Mode — (`engine/src/engine.rs`)

---

### Summary

In silo mode with `fixed_gas` configured, `charge_gas` deducts only `fixed_gas * effective_gas_price` from the sender's balance, but the EVM executor is unconditionally given `transaction.gas_limit` as its gas budget. Because `refund_unused_gas` also settles the relayer reward using `fixed_gas` (not actual `gas_used`), a sender who sets `gas_limit >> fixed_gas` can drive the EVM to consume far more gas than they paid for, with the relayer absorbing the shortfall on every such transaction.

---

### Finding Description

**`charge_gas` — fee deduction uses `fixed_gas`** [1](#0-0) 

When `fixed_gas` is present, `prepaid_amount = fixed_gas * effective_gas_price`. The sender's balance is reduced by this amount only.

**Guard — only rejects `fixed_gas > gas_limit`, not `gas_limit >> fixed_gas`** [2](#0-1) 

The only validation is that `fixed_gas ≤ transaction.gas_limit`. A transaction with `fixed_gas = 50 000` and `gas_limit = 30 000 000` passes this check without error.

**EVM executor receives `transaction.gas_limit`, not `fixed_gas`** [3](#0-2) [4](#0-3) 

`gas_limit` is derived from `transaction.gas_limit` and passed directly to `engine.call` / `engine.deploy_code`. `fixed_gas` is never used to cap the executor's budget.

**`refund_unused_gas` — relayer reward also capped at `fixed_gas`, ignoring actual `gas_used`** [5](#0-4) 

When `fixed_gas` is set, `spent_amount = fixed_gas * effective_gas_price` regardless of how much gas the EVM actually consumed. `refund = prepaid_amount − spent_amount = 0`. The relayer receives only `fixed_gas * priority_fee_per_gas`, even if the EVM burned orders of magnitude more gas.

---

### Impact Explanation

**Insolvency.** In Aurora's accounting model, the ETH fees collected from users are the revenue that compensates relayers for the NEAR gas they spend submitting transactions. NEAR gas cost scales with actual EVM computation. When `gas_limit >> fixed_gas`, the EVM can consume (e.g.) 25 000 000 gas while the sender paid for only 50 000 gas. The relayer is underpaid by the full difference on every such transaction. Repeated exploitation drains the relayer's ETH balance and, at the protocol level, creates a structural deficit between gas revenue and gas expenditure — cumulative insolvency.

---

### Likelihood Explanation

- Silo mode with `fixed_gas` is a supported, documented production feature.
- The guard at line 1066 explicitly permits `gas_limit > fixed_gas` (it only blocks the reverse).
- No whitelist is mandatory; if the silo's account/address whitelists are disabled (the default — `!list.is_enabled()` returns `true`), any caller can exploit this.
- The attacker needs only to craft a standard EVM transaction with a large `gas_limit` and gas-heavy bytecode — no privileged access required.

---

### Recommendation

Cap the EVM executor's gas budget at `fixed_gas` when it is set:

```rust
// engine/src/engine.rs — replace lines 1107-1110
let gas_limit: u64 = fixed_gas
    .map(|fg| fg.as_u256().min(transaction.gas_limit))
    .unwrap_or(transaction.gas_limit)
    .try_into()
    .map_err(|_| EngineErrorKind::GasOverflow)?;
```

This ensures the EVM can never consume more gas than the sender paid for, making `prepaid_amount ≥ gas_used * effective_gas_price` a true invariant.

---

### Proof of Concept

```
Setup:
  fixed_gas  = 50_000   (set by silo owner via set_silo_params)
  gas_price  = 1 Wei/gas
  gas_limit  = 30_000_000  (attacker-controlled field in the signed tx)

Step 1 — guard check (engine.rs:1066):
  fixed_gas (50_000) > gas_limit (30_000_000)?  → false → passes

Step 2 — charge_gas (engine.rs:496-500):
  prepaid_amount = 50_000 * 1 = 50_000 Wei  deducted from sender

Step 3 — EVM executor (engine.rs:1107-1138):
  executor budget = transaction.gas_limit = 30_000_000
  attacker deploys/calls a gas-burning loop; EVM uses 25_000_000 gas

Step 4 — refund_unused_gas (engine.rs:1274-1291):
  spent_amount  = fixed_gas * price = 50_000 * 1 = 50_000 Wei
  refund        = 50_000 - 50_000 = 0
  relayer_reward = fixed_gas * priority_fee = 50_000 * priority_fee

Invariant violation:
  ETH paid by sender  = 50_000 Wei
  ETH value of gas used = 25_000_000 Wei
  Deficit per tx      = 24_950_000 Wei absorbed by relayer

Repeated N times → relayer insolvency.
```

### Citations

**File:** engine/src/engine.rs (L496-500)
```rust
        let prepaid_amount = fixed_gas
            .map_or(transaction.gas_limit, EthGas::as_u256)
            .checked_mul(effective_gas_price)
            .map(Wei::new)
            .ok_or(GasPaymentError::EthAmountOverflow)?;
```

**File:** engine/src/engine.rs (L1065-1068)
```rust
    // Check that fixed gas is not greater than the gas limit from the transaction.
    if fixed_gas.is_some_and(|gas| gas.as_u256() > transaction.gas_limit) {
        return Err(EngineErrorKind::FixedGasOverflow.into());
    }
```

**File:** engine/src/engine.rs (L1107-1110)
```rust
    let gas_limit = transaction
        .gas_limit
        .try_into()
        .map_err(|_| EngineErrorKind::GasOverflow)?;
```

**File:** engine/src/engine.rs (L1116-1138)
```rust
    let result = if let Some(receiver) = transaction.to {
        engine.call(
            &sender,
            &receiver,
            transaction.value,
            transaction.data,
            gas_limit,
            access_list,
            transaction.authorization_list,
            handler,
        )
        // TODO: charge for storage
    } else {
        // Execute a contract deployment:
        engine.deploy_code(
            sender,
            transaction.value,
            transaction.data,
            None,
            gas_limit,
            access_list,
            handler,
        )
```

**File:** engine/src/engine.rs (L1274-1291)
```rust
    let (refund, relayer_reward) = {
        let gas_to_wei = |price: U256| {
            fixed_gas
                .map_or_else(|| gas_used.into(), EthGas::as_u256)
                .checked_mul(price)
                .map(Wei::new)
                .ok_or(GasPaymentError::EthAmountOverflow)
        };

        let spent_amount = gas_to_wei(gas_result.effective_gas_price)?;
        let reward_amount = gas_to_wei(gas_result.priority_fee_per_gas)?;

        let refund = gas_result
            .prepaid_amount
            .checked_sub(spent_amount)
            .ok_or(GasPaymentError::EthAmountOverflow)?;

        (refund, reward_amount)
```
