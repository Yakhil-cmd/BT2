### Title
Unchecked Signed Cast in `compute_gas_refund` Enables Incorrect Gas Accounting for Large Gas Limits — (File: `basic_bootloader/src/bootloader/transaction_flow/refund_calculation.rs`)

---

### Summary

`compute_gas_refund` computes a signed `delta_gas` value using unchecked `as i64` casts on `u64` quantities. For L2 transactions the ERGS_PER_GAS guard keeps all values below `i64::MAX`, but L1 (priority) transactions carry no equivalent cap. An attacker who submits an L1 transaction with `gas_limit > i64::MAX` causes the `gas_used as i64` cast to wrap to a large negative value, making `delta_gas` a large positive value, which is then added back to `gas_used` as a `u64`. Depending on whether overflow-checks are enabled, this either panics (halting block processing) or silently wraps `gas_used` to near-zero, giving the attacker a full gas refund while the operator receives nothing.

---

### Finding Description

In `compute_gas_refund`:

```rust
let delta_gas = if native_per_gas == 0 {
    0
} else {
    (native_used / native_per_gas) as i64 - (gas_used as i64)   // line 72
};

if delta_gas > 0 {
    gas_used += delta_gas as u64;   // line 78
}
``` [1](#0-0) 

Both `native_used / native_per_gas` and `gas_used` are `u64`. The `as i64` cast is a Rust truncating (wrapping) cast — it is the direct analog of Solidity's `intToUint` returning an absolute value: a value that exceeds `i64::MAX` silently becomes a large negative number instead of triggering an error.

For **L2 transactions** the guard at validation time is:

```rust
require!(
    tx_gas_limit.saturating_mul(ERGS_PER_GAS) < u64::MAX,
    internal_error!("TX gas limit overflows ergs counter"),
    system
)?;
``` [2](#0-1) 

`ERGS_PER_GAS = 256`, so `gas_limit < u64::MAX / 256 ≈ 7.2 × 10¹⁶ < i64::MAX ≈ 9.2 × 10¹⁸`. All casts are safe for L2 transactions.

For **L1 (priority) transactions** no equivalent check exists. The code explicitly notes that L1 gas limits are not validated by the bootloader:

```rust
// L1 transactions might have a gas limit < minimal_gas_used. This should be
// prevented by L1 validation, but we log and saturate if it happens.
if gas_limit < minimal_gas_used { system_log!(...); }
let minimal_gas_used = minimal_gas_used.min(gas_limit);
``` [3](#0-2) 

With `gas_limit > i64::MAX` and all gas consumed (`gas_used ≈ gas_limit`):

1. `gas_used as i64` wraps to a large negative value (e.g., `i64::MIN`).
2. `(native_used / native_per_gas) as i64` is a small non-negative value `V`.
3. `delta_gas = V − (large negative) = V + |large negative|` → large positive `i64`.
4. `gas_used += delta_gas as u64` overflows `u64`.
   - With `overflow-checks = true` (debug/safe release): **panic → InternalError → block halted**.
   - With `overflow-checks = false`: `gas_used` wraps to near-zero.

In the wrap case, the subsequent L1 refund calculation:

```rust
let pay_to_operator = U256::from(gas_used)          // ≈ 0
    .checked_mul(U256::from(gas_price))
    .ok_or(internal_error!("gu*gp"))?;
// ...
let to_refund_recipient = total_deposited
    .checked_sub(pay_to_operator)                   // ≈ total_deposited
    .ok_or(internal_error!("td-pto"))?;
``` [4](#0-3) 

returns the entire deposit to

### Citations

**File:** basic_bootloader/src/bootloader/transaction_flow/refund_calculation.rs (L69-79)
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
```

**File:** basic_bootloader/src/bootloader/transaction_flow/ethereum/validation_impl.rs (L116-120)
```rust
    require!(
        tx_gas_limit.saturating_mul(ERGS_PER_GAS) < u64::MAX,
        internal_error!("TX gas limit overflows ergs counter"),
        system
    )?;
```

**File:** basic_bootloader/src/bootloader/transaction_flow/zk/process_l1_transaction.rs (L277-334)
```rust
    let pay_to_operator = U256::from(gas_used)
        .checked_mul(U256::from(gas_price))
        .ok_or(internal_error!("gu*gp"))?;
    // Use FORMAL_INFINITE for post-execution operations (coinbase transfer,
    // asset tracker notifications, refund transfer, log emission).
    // These cannot fail due to resource exhaustion. Their native cost is
    // accounted for as intrinsic and is not included in
    // computational_native_used (native_used only reflects native for
    // pubdata + native used for charged computation).
    let mut inf_resources = S::Resources::FORMAL_INFINITE;

    let coinbase = system.get_coinbase();
    // Mint operator fee portion of the deposit to coinbase.
    mint_base_token::<S, Config>(
        system,
        system_functions,
        memories.reborrow(),
        &pay_to_operator,
        &coinbase,
        l1_chain_id,
        &mut inf_resources,
        tracer,
        validator,
    )
    .map_err(|e| match e.root_cause() {
        RootCause::Runtime(RuntimeError::OutOfErgs(_)) => {
            internal_error!("Out of ergs on infinite ergs").into()
        }
        RootCause::Runtime(RuntimeError::FatalRuntimeError(_)) => {
            internal_error!("Out of native on infinite").into()
        }
        _ => e,
    })?;

    // Refund
    let to_refund_recipient = if !is_success {
        // Upgrade transactions must always succeed
        if !is_priority_op {
            return Err(internal_error!("Upgrade transaction must succeed").into());
        }
        // If the transaction reverts, then the minting of the deposit
        // reverted too. Thus, we need to refund the entire deposit minus
        // the fee (`pay_to_operator`).
        total_deposited
            .checked_sub(pay_to_operator)
            .ok_or(internal_error!("td-pto"))
    } else {
        // If the transaction succeeds, then it is assumed that the
        // mint to `from` address was transferred correctly too.
        // In this case, we just refund the unused gas that the
        // transaction paid for initially.
        let prepaid_fee = gas_price
            .checked_mul(U256::from(transaction.gas_limit.read()))
            .ok_or(internal_error!("gp*gl"))?;
        prepaid_fee
            .checked_sub(pay_to_operator)
            .ok_or(internal_error!("pf-pto"))
    }?;
```

**File:** basic_bootloader/src/bootloader/transaction_flow/zk/process_l1_transaction.rs (L528-537)
```rust
    // L1 transactions might have a gas limit < minimal_gas_used. This should be
    // prevented by L1 validation, but we log and saturate if it happens.
    if gas_limit < minimal_gas_used {
        system_log!(
            system,
            "L1 tx gas limit below intrinsic cost, using saturated arithmetic instead"
        );
    }
    // Pick the min to keep processing L1 txs even if the L1 validation is wrong.
    let minimal_gas_used = minimal_gas_used.min(gas_limit);
```
