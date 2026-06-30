### Title
Floor Gas (EIP-7623) Amount Computed But Never Applied to Actual Gas Charging — (`engine/src/engine.rs`)

### Summary
The `floor_gas` value mandated by EIP-7623 is computed and validated against `gas_limit`, but is silently discarded and never used in the actual post-execution gas charging. The engine charges users only `gas_used × price` instead of the protocol-required `max(gas_used, floor_gas) × price`. Any unprivileged user submitting a high-calldata transaction to a contract with simple execution can systematically underpay gas fees, and relayers are correspondingly underpaid their priority-fee reward.

### Finding Description

In `engine/src/engine.rs`, the `submit_transaction` function computes both `intrinsic_gas` and `floor_gas` and validates that `gas_limit ≥ max(intrinsic_gas, floor_gas)`:

```rust
let intrinsic_gas = transaction.intrinsic_gas(CONFIG)...;
let floor_gas    = transaction.floor_gas(CONFIG)...;

if transaction.gas_limit < core::cmp::max(intrinsic_gas, floor_gas).into() {
    return Err(EngineErrorKind::IntrinsicGasNotMet.into());
}
``` [1](#0-0) 

After this check, `floor_gas` is never referenced again. The EVM executor is invoked with only `gas_limit` as its budget and has no knowledge of `floor_gas`. After execution, `refund_unused_gas` is called with only `gas_used`:

```rust
let gas_used = match &result {
    Ok(submit_result) => submit_result.gas_used,
    Err(engine_err)   => engine_err.gas_used,
};
refund_unused_gas(&mut io, &sender, gas_used, &prepaid_amount, &relayer_address, fixed_gas)...;
``` [2](#0-1) 

Inside `refund_unused_gas`, the amount charged is computed purely from `gas_used`:

```rust
let gas_to_wei = |price: U256| {
    fixed_gas
        .map_or_else(|| gas_used.into(), EthGas::as_u256)
        .checked_mul(price)
        .map(Wei::new)
        ...
};
let spent_amount = gas_to_wei(gas_result.effective_gas_price)?;
``` [3](#0-2) 

`floor_gas` is a gas *amount* (units), not a gas *cost* (Wei). The analogous error to the reference report is that the floor-gas *amount* is validated for the gas-limit check but is never converted to a gas *cost* and applied to the actual charge. The correct charge is `max(gas_used, floor_gas) × effective_gas_price`, but the engine charges only `gas_used × effective_gas_price`.

The `floor_gas` formula in `engine-transactions/src/lib.rs` produces a value strictly greater than `intrinsic_gas` whenever the transaction contains non-zero calldata bytes:

```rust
tokens_in_calldata          // = non_zero_bytes * 4 + zero_bytes
    .checked_mul(config.total_cost_floor_per_token)   // = 10 per token
    .and_then(|gas| gas.checked_add(base_gas))
``` [4](#0-3) 

For `n` non-zero bytes: `intrinsic_gas = 21000 + 16n`, `floor_gas = 21000 + 40n`. The gap is `24n` gas units. The EVM executor charges only `intrinsic_gas` upfront and then charges for execution; for a simple call, `gas_used ≈ intrinsic_gas ≪ floor_gas`.

The engine uses the Prague config globally:

```rust
const CONFIG: &Config = &Config::prague();
``` [5](#0-4) 

Prague enables `has_floor_gas = true`, so this path is always active in production.

### Impact Explanation

A user submitting a transaction with `n = 1000` non-zero calldata bytes to a contract performing minimal work:

| Quantity | Value |
|---|---|
| `intrinsic_gas` | `21 000 + 16 × 1000 = 37 000` |
| `floor_gas` | `21 000 + 40 × 1000 = 61 000` |
| `gas_used` (simple call) | `≈ 37 000` |
| Charged (actual) | `37 000 × price` |
| Should be charged | `61 000 × price` |
| Underpayment | `24 000 × price` per transaction |

The relayer receives `gas_used × priority_fee_per_gas` instead of `floor_gas × priority_fee_per_gas`. The relayer is systematically underpaid their priority-fee reward — a theft of unclaimed yield. The sender retains ETH that the protocol mandates should be consumed. The EIP-7623 floor-gas mechanism is entirely bypassed at the charging layer.

### Likelihood Explanation

High. The attack requires no privilege: any EOA can craft a transaction with arbitrary calldata. The floor gas is active in the Prague config used by the production engine. The condition `floor_gas > gas_used` is trivially satisfied by any transaction with non-zero calldata and simple execution (e.g., a call to a contract that reads a storage slot or does a simple transfer). No external oracle, admin key, or governance action is required.

### Recommendation

Pass `floor_gas` through to `refund_unused_gas` and apply it as the minimum gas charged:

```rust
// In submit_transaction, after computing floor_gas and gas_used:
let effective_gas_used = core::cmp::max(gas_used, floor_gas);
refund_unused_gas(&mut io, &sender, effective_gas_used, &prepaid_amount, &relayer_address, fixed_gas)?;
```

Alternatively, add a `floor_gas: u64` parameter to `refund_unused_gas` and replace `gas_used` with `max(gas_used, floor_gas)` inside the `gas_to_wei` closure.

### Proof of Concept

1. User constructs a Legacy transaction: `data = [0x01u8; 1000]`, `gas_limit = 61_001`, `gas_price = 10`.
2. Engine computes `floor_gas = 61 000`, `intrinsic_gas = 37 000`; check passes (`61 001 ≥ 61 000`).
3. EVM executor is invoked with `gas_limit = 61 001`; it charges `37 000` intrinsic gas and the call body uses negligible additional gas. `gas_used = 37 000`.
4. `refund_unused_gas` is called with `gas_used = 37 000`.
5. `spent_amount = 37 000 × 10 = 370 000 Wei`; `refund = 610 010 − 370 000 = 240 010 Wei` returned to sender.
6. Sender pays `370 000 Wei` instead of the EIP-7623-mandated `610 000 Wei`.
7. Relayer receives `37 000 × priority_fee` instead of `61 000 × priority_fee`.
8. Underpayment: `240 000 Wei` per transaction, scalable linearly with calldata size.

### Citations

**File:** engine/src/engine.rs (L433-433)
```rust
const CONFIG: &Config = &Config::prague();
```

**File:** engine/src/engine.rs (L1070-1081)
```rust
    let intrinsic_gas = transaction
        .intrinsic_gas(CONFIG)
        .map_err(|_| EngineErrorKind::GasOverflow)?;
    let floor_gas = transaction
        .floor_gas(CONFIG)
        .map_err(|_| EngineErrorKind::GasOverflow)?;

    // Check that the max value of intrinsic gas and floor gas is covered by the transaction
    // gas limit, EIP-7623 https://eips.ethereum.org/EIPS/eip-7623
    if transaction.gas_limit < core::cmp::max(intrinsic_gas, floor_gas).into() {
        return Err(EngineErrorKind::IntrinsicGasNotMet.into());
    }
```

**File:** engine/src/engine.rs (L1143-1159)
```rust
    let gas_used = match &result {
        Ok(submit_result) => submit_result.gas_used,
        Err(engine_err) => engine_err.gas_used,
    };

    refund_unused_gas(
        &mut io,
        &sender,
        gas_used,
        &prepaid_amount,
        &relayer_address,
        fixed_gas,
    )
    .map_err(|e| EngineError {
        gas_used,
        kind: EngineErrorKind::GasPayment(e),
    })?;
```

**File:** engine/src/engine.rs (L1274-1289)
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
```

**File:** engine-transactions/src/lib.rs (L239-247)
```rust
            let tokens_in_calldata = num_non_zero_bytes
                .checked_mul(4)
                .and_then(|gas| gas.checked_add(num_zero_bytes))
                .ok_or(Error::GasOverflow)?;

            tokens_in_calldata
                .checked_mul(config.total_cost_floor_per_token)
                .and_then(|gas| gas.checked_add(base_gas))
                .ok_or(Error::GasOverflow)
```
