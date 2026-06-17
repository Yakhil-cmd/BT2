### Title
`native_per_pubdata` Computed with Floor Division Instead of Ceiling Division Allows Underpayment for Pubdata Native Resources - (`basic_bootloader/src/bootloader/transaction_flow/zk/validation_impl.rs`)

---

### Summary

In ZKsync OS's L2 transaction validation, `native_per_pubdata` is computed using `wrapping_div` (floor/truncating division) instead of `div_ceil` (ceiling division). This is directly inconsistent with `native_per_gas`, which explicitly uses `div_ceil`. When `pubdata_price < native_price`, the floor division produces `native_per_pubdata = 0`, meaning the user pays zero native resources for all pubdata consumed in the transaction — a 100% native resource fee loss for pubdata.

---

### Finding Description

In `validation_impl.rs` line 142, `native_per_pubdata` is computed as:

```rust
let native_per_pubdata = u256_try_to_u64(&pubdata_price.wrapping_div(native_price))
    .ok_or(TxError::Validation(InvalidTransaction::PubdataPriceTooHigh))?;
``` [1](#0-0) 

Compare this to `native_per_gas` computed just above it at line 135:

```rust
u256_try_to_u64(&gas_price.div_ceil(native_price)).ok_or(TxError::Validation(
    InvalidTransaction::NativeResourcesAreTooExpensive,
))?
``` [2](#0-1) 

`native_per_gas` uses `div_ceil` (ceiling division), but `native_per_pubdata` uses `wrapping_div` (floor division). The same inconsistency is present in `api/src/helpers.rs`:

```rust
// native_per_gas = ceil(gas_price / native_price)
let native_per_gas = u256_try_to_u64(&gas_price.div_ceil(native_price)).ok_or(())?;

// native_per_pubdata = pubdata_price / native_price
let native_per_pubdata = u256_try_to_u64(&pubdata_price.wrapping_div(native_price)).ok_or(())?;
``` [3](#0-2) 

The `native_per_pubdata` value is then used in two places:

1. **Intrinsic pubdata overhead** deducted from the native limit at resource creation time (`native_per_pubdata_byte.saturating_mul(intrinsic_pubdata)`).
2. **Post-execution pubdata charge** via `get_resources_to_charge_for_pubdata`, which charges `current_pubdata_spent * native_per_pubdata` native units. [4](#0-3) 

When `pubdata_price < native_price` (e.g., `pubdata_price = 9`, `native_price = 10`), `floor(9 / 10) = 0`, so `native_per_pubdata = 0`. The user is charged **zero native resources** for every byte of pubdata they write, regardless of how much pubdata they generate.

Additionally, the `delta_gas` adjustment in `refund_calculation.rs` line 72 also uses floor division:

```rust
(native_used / native_per_gas) as i64 - (gas_used as i64)
``` [5](#0-4) 

This means the gas charged for native resource consumption is also rounded down, allowing users to underpay by up to 1 gas unit per transaction.

---

### Impact Explanation

The native resource models the off-chain proving cost (RISC-V cycles). Pubdata is a major driver of proving cost. When `native_per_pubdata = 0`:

- The user's native resource budget is not reduced by pubdata consumption at all.
- The user can write arbitrarily large amounts of pubdata without any native resource cost.
- The protocol/operator must absorb the full proving cost of the pubdata without native resource compensation.

This is a **resource accounting bug** leading to a **public funds-loss path**: the operator proves pubdata at their own cost while the user pays nothing in native resources for it. Any user can trigger this whenever `pubdata_price < native_price` is set by the operator.

---

### Likelihood Explanation

The operator sets both `pubdata_price` and `native_price` as block-level parameters. If the operator sets `pubdata_price` to any value strictly less than `native_price` (e.g., due to market conditions, misconfiguration, or a deliberate pricing model where pubdata is "cheap"), `native_per_pubdata` becomes 0 for all transactions in that block. Any unprivileged transaction sender can then exploit this by sending transactions that generate large amounts of pubdata (e.g., many storage writes), paying zero native resources for the proving cost of that pubdata. The attacker's entry path is simply submitting a normal L2 transaction.

---

### Recommendation

Replace `wrapping_div` with `div_ceil` for `native_per_pubdata` in both locations:

**`basic_bootloader/src/bootloader/transaction_flow/zk/validation_impl.rs` line 142:**
```rust
let native_per_pubdata = u256_try_to_u64(&pubdata_price.div_ceil(native_price))
    .ok_or(TxError::Validation(InvalidTransaction::PubdataPriceTooHigh))?;
```

**`api/src/helpers.rs` line 427:**
```rust
let native_per_pubdata = u256_try_to_u64(&pubdata_price.div_ceil(native_price)).ok_or(())?;
```

For the `delta_gas` calculation in `refund_calculation.rs`, consider using `div_ceil` as well:
```rust
native_used.div_ceil(native_per_gas) as i64 - (gas_used as i64)
``` [5](#0-4) 

---

### Proof of Concept

1. Operator sets `pubdata_price = 9`, `native_price = 10` (a realistic scenario where pubdata is priced slightly below one native unit).
2. `native_per_pubdata = floor(9 / 10) = 0`.
3. Attacker sends a transaction that writes to 100 storage slots (generating ~3200 bytes of pubdata).
4. `get_resources_to_charge_for_pubdata` charges `3200 * 0 = 0` native resources for pubdata.
5. The attacker pays zero native resources for the pubdata proving cost.
6. The operator must prove the pubdata (costing `3200 * 9 = 28800` native units worth of proving work) without native resource compensation.
7. Repeated across many transactions, this drains the operator's proving budget without compensation. [6](#0-5)

### Citations

**File:** basic_bootloader/src/bootloader/transaction_flow/zk/validation_impl.rs (L134-138)
```rust
        } else {
            u256_try_to_u64(&gas_price.div_ceil(native_price)).ok_or(TxError::Validation(
                InvalidTransaction::NativeResourcesAreTooExpensive,
            ))?
        }
```

**File:** basic_bootloader/src/bootloader/transaction_flow/zk/validation_impl.rs (L141-143)
```rust
    // We checked native_price != 0 above
    let native_per_pubdata = u256_try_to_u64(&pubdata_price.wrapping_div(native_price))
        .ok_or(TxError::Validation(InvalidTransaction::PubdataPriceTooHigh))?;
```

**File:** api/src/helpers.rs (L420-427)
```rust
    // native_per_gas = ceil(gas_price / native_price)
    if native_price.is_zero() {
        return Err(());
    }
    let native_per_gas = u256_try_to_u64(&gas_price.div_ceil(native_price)).ok_or(())?;

    // native_per_pubdata = pubdata_price / native_price
    let native_per_pubdata = u256_try_to_u64(&pubdata_price.wrapping_div(native_price)).ok_or(())?;
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

**File:** basic_bootloader/src/bootloader/transaction_flow/refund_calculation.rs (L69-73)
```rust
        let delta_gas = if native_per_gas == 0 {
            0
        } else {
            (native_used / native_per_gas) as i64 - (gas_used as i64)
        };
```
