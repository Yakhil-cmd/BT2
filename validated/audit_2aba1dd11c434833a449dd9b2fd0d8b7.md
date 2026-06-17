### Title
Saturating Overflow in `native_prepaid_from_gas` Grants Attacker Unbounded Pubdata Native Budget - (`File: basic_bootloader/src/bootloader/transaction_flow/zk/validation_impl.rs`)

### Summary
In `validation_impl.rs`, the computation `native_per_gas.saturating_mul(tx_gas_limit)` silently saturates to `u64::MAX` when the product overflows. This inflated value is passed directly into `create_resources_for_tx` as the native budget, causing the excess above `MAX_NATIVE_COMPUTATIONAL` to be "withheld" as a near-`u64::MAX` pubdata reserve. The user can then generate far more pubdata than they paid for, with the withheld pool absorbing the cost.

### Finding Description

In `validate_and_compute_fee_for_transaction` (ZK transaction path), the native resource limit is derived as:

```rust
// validation_impl.rs line 144
let native_prepaid_from_gas = native_per_gas.saturating_mul(tx_gas_limit);
``` [1](#0-0) 

`native_per_gas` is a `u64` derived from `gas_price.div_ceil(native_price)`, bounded only by `u64::MAX`. `tx_gas_limit` is a `u64` bounded by the check:

```rust
require!(
    tx_gas_limit.saturating_mul(ERGS_PER_GAS) < u64::MAX, // ERGS_PER_GAS = 256
    ...
)?;
``` [2](#0-1) 

This constrains `tx_gas_limit < u64::MAX / 256 ≈ 7.2 × 10¹⁶`. For `native_per_gas * tx_gas_limit` to overflow `u64`, only `native_per_gas > 256` is required — trivially achievable by setting `max_fee_per_gas = 257 * native_price`.

When the product overflows, `saturating_mul` returns `u64::MAX`. This value is passed to `create_resources_for_tx`:

```rust
let tx_resources = create_resources_for_tx::<S, L2ResourcesPolicy>(
    system,
    tx_gas_limit,
    native_per_gas == 0,
    native_prepaid_from_gas,   // u64::MAX when overflowed
    ...
)?;
``` [3](#0-2) 

Inside `create_resources_for_tx`, the native limit is capped at `MAX_NATIVE_COMPUTATIONAL`, and the excess is placed into a "withheld" pool reserved for pubdata charges:

```rust
let (native_limit, withheld) = if native_limit <= MAX_NATIVE_COMPUTATIONAL {
    (native_limit, S::Resources::from_ergs(Ergs::empty()))
} else {
    let withheld = native_limit - MAX_NATIVE_COMPUTATIONAL; // ≈ u64::MAX when overflowed
    (MAX_NATIVE_COMPUTATIONAL, S::Resources::from_native(withheld))
};
``` [4](#0-3) 

The withheld pool is reclaimed after execution to pay for pubdata:

```rust
context.resources.main_resources.reclaim_withheld(context.resources.withheld.take());
``` [5](#0-4) 

With `withheld ≈ u64::MAX`, the user has a near-infinite pubdata budget. The `get_resources_to_charge_for_pubdata` function charges pubdata from this pool:

```rust
let native = current_pubdata_spent
    .checked_mul(native_per_pubdata)
    .ok_or(out_of_native_resources!())?;
``` [6](#0-5) 

Because the withheld pool is `≈ u64::MAX`, the pubdata charge will succeed for any realistic pubdata amount, regardless of what the user actually paid.

The same saturation recurs in `refund_calculation.rs` line 62, where `full_native_limit` is recomputed:

```rust
gas_limit.saturating_mul(native_per_gas)
``` [7](#0-6) 

This causes `native_used` to be computed as `u64::MAX - remaining`, a near-maximal value, further corrupting the `delta_gas` accounting and the final gas refund.

### Impact Explanation

An attacker can generate an unbounded amount of pubdata (storage writes, events, etc.) within a single transaction without paying the correct native fee. The sequencer and prover must process and publish this pubdata at a loss. This constitutes a **resource accounting bug** enabling underpayment for pubdata, which can be used to bloat chain state or exhaust pubdata capacity at minimal cost.

### Likelihood Explanation

The trigger condition (`native_per_gas > 256`) is trivially reachable by any unprivileged L2 transaction sender. No special access, governance role, or oracle manipulation is required. The attacker simply sets `max_fee_per_gas` to a value slightly above `256 * native_price` and uses a near-maximum gas limit.

### Recommendation

Replace the unchecked `saturating_mul` with a `checked_mul` that rejects the transaction if the product overflows:

```rust
let native_prepaid_from_gas = native_per_gas
    .checked_mul(tx_gas_limit)
    .ok_or(TxError::Validation(InvalidTransaction::NativeResourcesAreTooExpensive))?;
```

Apply the same fix to the corresponding computation in `refund_calculation.rs` line 62.

### Proof of Concept

1. Deploy any contract that performs many storage writes (pubdata-heavy).
2. Submit an L2 transaction with:
   - `max_fee_per_gas = 257 * native_price` (so `native_per_gas = 257`)
   - `gas_limit = u64::MAX / 256 - 1` (maximum allowed by the ergs check)
3. `native_per_gas * gas_limit = 257 * (u64::MAX/256 - 1) > u64::MAX` → saturates to `u64::MAX`.
4. `withheld ≈ u64::MAX - MAX_NATIVE_COMPUTATIONAL ≈ u64::MAX`.
5. The transaction executes with a near-infinite pubdata budget; the pubdata charge is absorbed by the withheld pool regardless of actual pubdata consumed.
6. The attacker pays only `gas_price * gas_limit` tokens but generates pubdata worth orders of magnitude more in native resources.

### Citations

**File:** basic_bootloader/src/bootloader/transaction_flow/zk/validation_impl.rs (L144-144)
```rust
    let native_prepaid_from_gas = native_per_gas.saturating_mul(tx_gas_limit);
```

**File:** basic_bootloader/src/bootloader/transaction_flow/zk/validation_impl.rs (L193-202)
```rust
    let tx_resources = create_resources_for_tx::<S, L2ResourcesPolicy>(
        system,
        tx_gas_limit,
        native_per_gas == 0,
        native_prepaid_from_gas,
        native_per_pubdata,
        intrinsic_gas,
        intrinsic_computational_native,
        intrinsic_pubdata,
    )?;
```

**File:** basic_bootloader/src/bootloader/transaction_flow/ethereum/validation_impl.rs (L116-120)
```rust
    require!(
        tx_gas_limit.saturating_mul(ERGS_PER_GAS) < u64::MAX,
        internal_error!("TX gas limit overflows ergs counter"),
        system
    )?;
```

**File:** basic_bootloader/src/bootloader/transaction_flow/gas_helpers.rs (L368-380)
```rust
    let (native_limit, withheld) = if native_limit <= MAX_NATIVE_COMPUTATIONAL {
        (native_limit, S::Resources::from_ergs(Ergs::empty()))
    } else {
        let withheld =
            <<S as zk_ee::system::SystemTypes>::Resources as Resources>::Native::from_computational(
                native_limit - MAX_NATIVE_COMPUTATIONAL,
            );

        (
            MAX_NATIVE_COMPUTATIONAL,
            S::Resources::from_native(withheld),
        )
    };
```

**File:** basic_bootloader/src/bootloader/transaction_flow/gas_helpers.rs (L430-432)
```rust
    let native = current_pubdata_spent
        .checked_mul(native_per_pubdata)
        .ok_or(out_of_native_resources!())?;
```

**File:** basic_bootloader/src/bootloader/transaction_flow/zk/mod.rs (L389-392)
```rust
        context
            .resources
            .main_resources
            .reclaim_withheld(context.resources.withheld.take());
```

**File:** basic_bootloader/src/bootloader/transaction_flow/refund_calculation.rs (L62-62)
```rust
        gas_limit.saturating_mul(native_per_gas)
```
