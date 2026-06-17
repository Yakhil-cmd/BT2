### Title
Truncating Integer Division in `native_per_pubdata` Computation Causes Pubdata to Be Free When `pubdata_price < native_price` - (File: `basic_bootloader/src/bootloader/transaction_flow/zk/validation_impl.rs`)

### Summary

In `validate_zk_transaction` (ZK transaction validation path), `native_per_pubdata` is computed using floor (truncating) integer division via `wrapping_div`. When the operator-supplied `pubdata_price` is less than `native_price`, the result truncates to zero. With `native_per_pubdata == 0`, every pubdata-cost check passes unconditionally, allowing any unprivileged user to write unlimited L1 pubdata at zero native-resource cost. This is the direct analog of the BlueberryStaking `_fetchTWAP` bug: a price-conversion step silently produces zero due to integer truncation, making a paid resource effectively free.

### Finding Description

**Root cause — floor division instead of ceiling division:**

In `basic_bootloader/src/bootloader/transaction_flow/zk/validation_impl.rs` line 142:

```rust
// We checked native_price != 0 above
let native_per_pubdata = u256_try_to_u64(&pubdata_price.wrapping_div(native_price))
    .ok_or(TxError::Validation(InvalidTransaction::PubdataPriceTooHigh))?;
```

`wrapping_div` performs floor (truncating) integer division. When `pubdata_price < native_price`, the result is `0`. The same pattern appears in `api/src/helpers.rs` line 427:

```rust
// native_per_pubdata = pubdata_price / native_price
let native_per_pubdata = u256_try_to_u64(&pubdata_price.wrapping_div(native_price)).ok_or(())?;
```

**Contrast with `native_per_gas`:** The sibling calculation on line 135 uses `div_ceil` (ceiling division) to ensure the user always pays at least the correct amount for gas:

```rust
u256_try_to_u64(&gas_price.div_ceil(native_price)).ok_or(TxError::Validation(
    InvalidTransaction::NativeResourcesAreTooExpensive,
))?
```

The asymmetry — `div_ceil` for gas, `wrapping_div` (floor) for pubdata — is the bug.

**Propagation to zero-cost pubdata:**

`native_per_pubdata` flows into `create_resources_for_tx` in `basic_bootloader/src/bootloader/transaction_flow/gas_helpers.rs` line 352:

```rust
let intrinsic_pubdata_overhead = native_per_pubdata_byte.saturating_mul(intrinsic_pubdata);
```

When `native_per_pubdata == 0`, `intrinsic_pubdata_overhead == 0` — no native resources are reserved for intrinsic pubdata.

It also flows into `get_resources_to_charge_for_pubdata` at line 430–432:

```rust
let native = current_pubdata_spent
    .checked_mul(native_per_pubdata)
    .ok_or(out_of_native_resources!())?;
```

When `native_per_pubdata == 0`, `native == 0` for any amount of pubdata spent. Consequently, `check_enough_resources_for_pubdata` always returns `has_enough = true`, and the post-execution pubdata revert path is never triggered.

**Trigger condition:** The operator sets `pubdata_price < native_price`. There is no validation preventing this. The test harness in `tests/evm_divergence_validator/src/runner.rs` line 491 already demonstrates this configuration:

```rust
native_price: ruint::aliases::U256::from(10u64),
pubdata_price: Default::default(), // = 0
```

### Impact Explanation

When `native_per_pubdata == 0`:

1. Any unprivileged user can submit transactions that write an arbitrary number of storage slots (pubdata) to L1 without paying any native resource cost for it.
2. The operator bears the full L1 data-availability cost (calldata / blob fees) for the attacker's pubdata.
3. The pubdata limit (`get_pubdata_limit`) is the only remaining guard, but it is a per-block cap, not a per-transaction economic deterrent. An attacker can fill every block to the pubdata limit at near-zero cost.
4. This constitutes direct financial loss to the operator and potential L1 data-availability exhaustion (DoS of the pubdata channel).

**Severity:** High — direct financial loss to the operator/protocol, reachable by any unprivileged transaction sender.

### Likelihood Explanation

The condition `pubdata_price < native_price` is reachable in practice:

- During initial deployment or chain configuration, an operator may set `pubdata_price` to a low value (or leave it at the default of `0`) while `native_price` is set to a non-zero value.
- The code contains no assertion or validation that `pubdata_price >= native_price`.
- The existing test suite explicitly uses `pubdata_price = 0` with `native_price = 10`, confirming the configuration is considered valid by the system.
- An attacker monitoring on-chain block metadata can detect when `pubdata_price < native_price` and immediately begin exploiting the free-pubdata window.

### Recommendation

Replace `wrapping_div` with `div_ceil` for `native_per_pubdata`, mirroring the treatment of `native_per_gas`:

```rust
// Before (floor division — can produce 0):
let native_per_pubdata = u256_try_to_u64(&pubdata_price.wrapping_div(native_price))
    .ok_or(TxError::Validation(InvalidTransaction::PubdataPriceTooHigh))?;

// After (ceiling division — consistent with native_per_gas):
let native_per_pubdata = u256_try_to_u64(&pubdata_price.div_ceil(native_price))
    .ok_or(TxError::Validation(InvalidTransaction::PubdataPriceTooHigh))?;
```

Apply the same fix in `api/src/helpers.rs` line 427. Additionally, add a validation that `pubdata_price > 0` (or at minimum document the zero-pubdata-price behavior and its security implications).

### Proof of Concept

**Setup:**
- Operator sets `native_price = 10`, `pubdata_price = 5` (or `pubdata_price = 0`).
- `native_per_pubdata = 5 / 10 = 0` (floor division).

**Exploit:**
1. Attacker submits an EIP-1559 transaction with `max_fee_per_gas = 10`, `gas_limit = 1_000_000`.
2. `native_per_gas = ceil(10 / 10) = 1`; `native_prepaid_from_gas = 1_000_000`.
3. `native_per_pubdata = 0`.
4. Transaction calls a contract that writes 10,000 storage slots (generating ~320,000 bytes of pubdata).
5. In `get_resources_to_charge_for_pubdata`: `native = 320_000 * 0 = 0`.
6. `check_enough_resources_for_pubdata` returns `has_enough = true`.
7. Transaction succeeds; 320,000 bytes of pubdata are published to L1 at zero pubdata cost to the attacker.
8. Operator pays the full L1 blob/calldata fee for the attacker's data.

**Relevant code locations:** [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4)

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

**File:** api/src/helpers.rs (L426-427)
```rust
    // native_per_pubdata = pubdata_price / native_price
    let native_per_pubdata = u256_try_to_u64(&pubdata_price.wrapping_div(native_price)).ok_or(())?;
```

**File:** basic_bootloader/src/bootloader/transaction_flow/gas_helpers.rs (L351-353)
```rust
    // Charge intrinsic pubdata
    let intrinsic_pubdata_overhead = native_per_pubdata_byte.saturating_mul(intrinsic_pubdata);
    let native_limit = match native_limit.checked_sub(intrinsic_pubdata_overhead) {
```

**File:** basic_bootloader/src/bootloader/transaction_flow/gas_helpers.rs (L430-432)
```rust
    let native = current_pubdata_spent
        .checked_mul(native_per_pubdata)
        .ok_or(out_of_native_resources!())?;
```
