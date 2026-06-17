### Title
Precision Loss in `native_per_pubdata` Calculation Causes Systematic Underpayment for Pubdata — (File: `basic_bootloader/src/bootloader/transaction_flow/zk/validation_impl.rs`)

---

### Summary

The `native_per_pubdata` rate used to charge native resources for pubdata is computed via integer floor division (`pubdata_price / native_price`), silently discarding the remainder. This causes users to systematically underpay for pubdata on every L2 ZK transaction. When `pubdata_price < native_price`, `native_per_pubdata` collapses to zero and pubdata is entirely free in native resources — a 100% loss of pubdata fees for the operator. The truncated residual accumulates irrecoverably across every transaction that generates pubdata.

---

### Finding Description

In `validate_and_compute_fee_for_transaction`, the `native_per_pubdata` rate is computed as:

```rust
// basic_bootloader/src/bootloader/transaction_flow/zk/validation_impl.rs, line 142
let native_per_pubdata = u256_try_to_u64(&pubdata_price.wrapping_div(native_price))
    .ok_or(TxError::Validation(InvalidTransaction::PubdataPriceTooHigh))?;
```

`wrapping_div` performs floor (integer) division. The remainder `pubdata_price % native_price` is silently discarded. This rate is then passed into `create_resources_for_tx` and ultimately used in `get_resources_to_charge_for_pubdata` to charge native resources for pubdata:

```rust
// basic_bootloader/src/bootloader/transaction_flow/gas_helpers.rs, lines 430-432
let native = current_pubdata_spent
    .checked_mul(native_per_pubdata)
    .ok_or(out_of_native_resources!())?;
```

The correct charge per pubdata byte should be `pubdata_price / native_price` (exact rational), but floor division means users are charged only `⌊pubdata_price / native_price⌋` native per pubdata byte. The residual `(pubdata_price % native_price) / native_price` native per pubdata byte is never collected and never carried forward.

The inconsistency is made explicit by comparing with the `native_per_gas` calculation in the same function, which uses **ceiling** division:

```rust
// basic_bootloader/src/bootloader/transaction_flow/zk/validation_impl.rs, line 135
u256_try_to_u64(&gas_price.div_ceil(native_price)).ok_or(...)
```

Gas costs are rounded **up** (operator-favorable); pubdata costs are rounded **down** (user-favorable). This asymmetry is the root cause. [1](#0-0) [2](#0-1) [3](#0-2) 

---

### Impact Explanation

**Severity: Low**

- **Extreme case** (`pubdata_price < native_price`): `native_per_pubdata = 0`. Any unprivileged transaction sender can generate pubdata without paying any native resources for it. The operator loses 100% of pubdata fees for all such transactions.
- **General case** (`pubdata_price % native_price != 0`): users underpay by `(pubdata_price % native_price) × pubdata_bytes / native_price` native per transaction. This residual is irrecoverable — there is no carry-forward mechanism.
- The lost amount accumulates with every transaction that generates pubdata, analogous to the MultiRewards `reward % rewardsDuration` residual accumulating in the contract.

---

### Likelihood Explanation

**Likelihood: High**

- Every L2 ZK transaction generating pubdata is affected whenever `pubdata_price % native_price ≠ 0`.
- In practice, `pubdata_price` and `native_price` are set from market conditions and are almost never exact multiples of each other.
- The condition `pubdata_price < native_price` is a realistic operational scenario (e.g., when pubdata is cheap relative to proving cost), and the code does not prevent it.
- No special attacker action is required beyond submitting ordinary transactions with storage writes. [4](#0-3) 

---

### Recommendation

Use ceiling division (`div_ceil`) for `native_per_pubdata` to match the `native_per_gas` calculation and ensure the operator is not systematically undercompensated:

```rust
let native_per_pubdata = u256_try_to_u64(&pubdata_price.div_ceil(native_price))
    .ok_or(TxError::Validation(InvalidTransaction::PubdataPriceTooHigh))?;
```

Alternatively, store the residual `pubdata_price % native_price` in block-level state and add it to the next `pubdata_price` before division, so no residual accumulates across transactions.

---

### Proof of Concept

1. Operator sets block context: `pubdata_price = 5`, `native_price = 10`.
2. `native_per_pubdata = 5 / 10 = 0` (floor division).
3. Any transaction that writes storage (generating pubdata) is charged `0 × pubdata_bytes = 0` native for pubdata.
4. The operator loses 100% of pubdata fees for every such transaction.
5. The lost amount accumulates irrecoverably with each transaction — the exact analog of the MultiRewards PoC where `rewardAmount = rewardDuration - 1` causes 100% reward loss.

For the general case: `pubdata_price = 7`, `native_price = 3` → `native_per_pubdata = 2` instead of the correct `2.33`. For a transaction generating 1000 pubdata bytes, the operator loses `0.33 × 1000 = 333` native units per transaction, accumulating indefinitely. [5](#0-4) [6](#0-5)

### Citations

**File:** basic_bootloader/src/bootloader/transaction_flow/zk/validation_impl.rs (L106-143)
```rust
    let pubdata_price = system.get_pubdata_price();
    let native_price = system.get_native_price();

    let gas_price = if transaction.is_service() {
        // Service transactions do not pay gas fees,
        // their gas price is allowed to be < block base fee.
        U256::ZERO
    } else {
        get_gas_price::<S, Config>(
            system,
            transaction.max_fee_per_gas(),
            transaction.max_priority_fee_per_gas(),
        )?
    };

    let native_per_gas = {
        if native_price.is_zero() {
            return Err(internal_error!("Native price cannot be 0").into());
        }

        if cfg!(feature = "resources_for_tester") {
            crate::bootloader::constants::TESTER_NATIVE_PER_GAS
        } else if Config::SIMULATION && gas_price.is_zero() {
            // For simulation, if gas price isn't set, we use base fee
            // for native calculation
            u256_try_to_u64(&system.get_eip1559_basefee().div_ceil(native_price)).ok_or(
                TxError::Validation(InvalidTransaction::NativeResourcesAreTooExpensive),
            )?
        } else {
            u256_try_to_u64(&gas_price.div_ceil(native_price)).ok_or(TxError::Validation(
                InvalidTransaction::NativeResourcesAreTooExpensive,
            ))?
        }
    };

    // We checked native_price != 0 above
    let native_per_pubdata = u256_try_to_u64(&pubdata_price.wrapping_div(native_price))
        .ok_or(TxError::Validation(InvalidTransaction::PubdataPriceTooHigh))?;
```

**File:** basic_bootloader/src/bootloader/transaction_flow/gas_helpers.rs (L422-435)
```rust
pub fn get_resources_to_charge_for_pubdata<S: EthereumLikeTypes>(
    system: &mut System<S>,
    native_per_pubdata: u64,
    base_pubdata: Option<u64>,
) -> Result<(u64, S::Resources), SystemError> {
    let current_pubdata_spent = system
        .net_pubdata_used()?
        .saturating_sub(base_pubdata.unwrap_or(0));
    let native = current_pubdata_spent
        .checked_mul(native_per_pubdata)
        .ok_or(out_of_native_resources!())?;
    let native = <S::Resources as zk_ee::system::Resources>::Native::from_computational(native);
    Ok((current_pubdata_spent, S::Resources::from_native(native)))
}
```

**File:** basic_bootloader/src/bootloader/transaction_flow/refund_calculation.rs (L20-33)
```rust
pub(crate) fn compute_gas_refund<S: EthereumLikeTypes>(
    system: &mut System<S>,
    to_charge_for_pubdata: S::Resources,
    gas_limit: u64,
    minimal_gas_used: u64,
    native_per_gas: u64,
    resources: &mut S::Resources,
) -> Result<RefundInfo, InternalError> {
    // Already checked
    resources.charge_unchecked(&to_charge_for_pubdata);

    let mut gas_used = gas_limit
        .checked_sub(resources.ergs().0.div_floor(ERGS_PER_GAS))
        .ok_or(internal_error!("gas remaining > gas limit"))?;
```
