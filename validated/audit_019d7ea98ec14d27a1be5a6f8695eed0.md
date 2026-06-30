### Title
`max_gas_price` in `submit_with_args` is not enforced against total effective gas price — (`engine/src/engine.rs`)

### Summary

The `max_gas_price` field in `SubmitArgs` is documented as "Max gas price the user is ready to pay for the transaction." However, in `charge_gas()`, this cap is applied only to the `priority_fee_per_gas` component, not to the total `effective_gas_price = priority_fee_per_gas + block_base_fee_per_gas`. When `block_base_fee_per_gas > 0`, the user's stated maximum is silently bypassed and they are charged more ETH per gas than they consented to.

### Finding Description

In `engine/src/engine.rs`, the `charge_gas()` function computes the effective gas price as follows:

```rust
let priority_fee_per_gas = transaction
    .max_priority_fee_per_gas
    .min(transaction.max_fee_per_gas - block_base_fee_per_gas);
let priority_fee_per_gas = max_gas_price.map_or(priority_fee_per_gas, |price| {
    price.min(priority_fee_per_gas)   // ← max_gas_price caps only the tip
});
let effective_gas_price = priority_fee_per_gas + block_base_fee_per_gas;  // ← base fee added unchecked
``` [1](#0-0) 

`max_gas_price` is applied as `price.min(priority_fee_per_gas)`, capping only the priority fee (tip). The `block_base_fee_per_gas` is then added on top without any comparison against `max_gas_price`. The resulting `effective_gas_price` — the rate at which the user's ETH balance is actually debited — can therefore exceed `max_gas_price` by the full value of `block_base_fee_per_gas`.

The prepaid amount charged to the sender is:

```rust
let prepaid_amount = fixed_gas
    .map_or(transaction.gas_limit, EthGas::as_u256)
    .checked_mul(effective_gas_price)   // effective_gas_price > max_gas_price
    .map(Wei::new)
    ...
``` [2](#0-1) 

The entry point is `submit_with_args`, which reads `args.max_gas_price` and passes it directly to `charge_gas`:

```rust
let max_gas_price = args.max_gas_price.map(Into::into);
let prepaid_amount = match engine.charge_gas(&sender, &transaction, max_gas_price, fixed_gas) {
``` [3](#0-2) 

The `SubmitArgs` struct documents the field as the maximum the user is willing to pay:

```rust
/// Max gas price the user is ready to pay for the transaction.
pub max_gas_price: Option<u128>,
``` [4](#0-3) 

This is structurally identical to the Launchpad bug: a user-specified upper bound is checked against only one component of a two-component total, allowing the actual charge to silently exceed the stated limit.

### Impact Explanation

When `block_base_fee_per_gas > 0`, any user calling `submit_with_args` with `max_gas_price` set pays `(priority_fee_capped + block_base_fee_per_gas) * gas_used` ETH, where `priority_fee_capped ≤ max_gas_price` but `effective_gas_price > max_gas_price`. The excess `block_base_fee_per_gas * gas_used` ETH is deducted from the user's on-chain balance without their consent. The user's `max_fee_per_gas` in the signed transaction bounds the absolute maximum, but the `max_gas_price` protection — the tighter, user-intended bound — is completely ineffective. This constitutes a gas/fee-accounting bug resulting in direct, unconsented ETH loss from user balances.

**Impact: High — theft of user funds (ETH over-charge beyond stated consent).**

### Likelihood Explanation

The bug is dormant when `block_base_fee_per_gas = 0`, which is Aurora's current default. However, Aurora supports EIP-1559 transactions with `max_fee_per_gas` / `max_priority_fee_per_gas` fields, meaning the base-fee mechanism is implemented and can be set to a non-zero value by the Aurora contract owner for legitimate EIP-1559 fee-market reasons. Any such configuration immediately activates the bug for all callers of `submit_with_args` who supply `max_gas_price`. No attacker compromise is required; the owner enabling a standard protocol feature is sufficient.

### Recommendation

Apply `max_gas_price` to the total `effective_gas_price`, not just the priority fee. The corrected logic should either:

1. Revert if `effective_gas_price > max_gas_price` after computing it, or
2. Derive the priority fee cap as `max_gas_price.saturating_sub(block_base_fee_per_gas)` before clamping:

```rust
let priority_fee_cap = max_gas_price.map(|p| p.saturating_sub(block_base_fee_per_gas));
let priority_fee_per_gas = priority_fee_cap.map_or(priority_fee_per_gas, |cap| {
    cap.min(priority_fee_per_gas)
});
let effective_gas_price = priority_fee_per_gas + block_base_fee_per_gas;
// Now effective_gas_price ≤ max_gas_price is guaranteed
```

### Proof of Concept

1. Aurora owner sets `block_base_fee_per_gas = 10` (legitimate EIP-1559 configuration).
2. User calls `submit_with_args` with `max_gas_price = 5`, transaction has `max_fee_per_gas = 30`, `max_priority_fee_per_gas = 20`, `gas_limit = 21_000`.
3. Inside `charge_gas()`:
   - `priority_fee_per_gas = min(20, 30 − 10) = 20`
   - After `max_gas_price` cap: `priority_fee_per_gas = min(5, 20) = 5`
   - `effective_gas_price = 5 + 10 = 15` ← exceeds user's stated max of 5
4. `prepaid_amount = 21_000 × 15 = 315_000 wei` is debited from the user.
5. User intended to pay at most `21_000 × 5 = 105_000 wei`.
6. Excess charge: `210_000 wei` taken without consent. The transaction succeeds with no error or warning.

### Citations

**File:** engine/src/engine.rs (L487-493)
```rust
        let priority_fee_per_gas = transaction
            .max_priority_fee_per_gas
            .min(transaction.max_fee_per_gas - block_base_fee_per_gas);
        let priority_fee_per_gas = max_gas_price.map_or(priority_fee_per_gas, |price| {
            price.min(priority_fee_per_gas)
        });
        let effective_gas_price = priority_fee_per_gas + block_base_fee_per_gas;
```

**File:** engine/src/engine.rs (L496-504)
```rust
        let prepaid_amount = fixed_gas
            .map_or(transaction.gas_limit, EthGas::as_u256)
            .checked_mul(effective_gas_price)
            .map(Wei::new)
            .ok_or(GasPaymentError::EthAmountOverflow)?;

        let new_balance = get_balance(&self.io, sender)
            .checked_sub(prepaid_amount)
            .ok_or(GasPaymentError::OutOfFund)?;
```

**File:** engine/src/engine.rs (L1100-1106)
```rust
    let max_gas_price = args.max_gas_price.map(Into::into);
    let prepaid_amount = match engine.charge_gas(&sender, &transaction, max_gas_price, fixed_gas) {
        Ok(gas_result) => gas_result,
        Err(err) => {
            return Err(EngineErrorKind::GasPayment(err).into());
        }
    };
```

**File:** engine-types/src/parameters/engine.rs (L136-138)
```rust
    /// Max gas price the user is ready to pay for the transaction.
    pub max_gas_price: Option<u128>,
    /// Address of the `ERC20` token the user prefers to pay in.
```
