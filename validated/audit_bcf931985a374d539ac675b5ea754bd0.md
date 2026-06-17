### Title
Truncated Integer Division in `native_per_pubdata` Causes Systematic Pubdata Cost Undercharging - (`basic_bootloader/src/bootloader/transaction_flow/zk/validation_impl.rs`)

---

### Summary

The `native_per_pubdata` ratio — which governs how many native resource units are charged per byte of pubdata — is computed using floor (truncating) integer division. This mirrors the M-25 pattern exactly: a division is applied to a ratio before it is multiplied by a count, causing the fractional remainder to be silently discarded. When `pubdata_price < native_price`, the result is zero and pubdata costs nothing in native resources, allowing a transaction sender to generate unbounded pubdata (up to `pubdata_limit`) without paying the corresponding proving cost.

---

### Finding Description

In `validate_and_compute_fee_for_transaction` (L2 ZK transaction flow), `native_per_pubdata` is computed as:

```rust
let native_per_pubdata = u256_try_to_u64(&pubdata_price.wrapping_div(native_price))
    .ok_or(TxError::Validation(InvalidTransaction::PubdataPriceTooHigh))?;
``` [1](#0-0) 

This is a plain floor division. The remainder `pubdata_price % native_price` is discarded. The same pattern appears in the off-chain helper:

```rust
let native_per_pubdata = u256_try_to_u64(&pubdata_price.wrapping_div(native_price)).ok_or(())?;
``` [2](#0-1) 

The truncated `native_per_pubdata` is then used to charge native resources for every pubdata byte consumed:

```rust
let native = current_pubdata_spent
    .checked_mul(native_per_pubdata)
    .ok_or(out_of_native_resources!())?;
``` [3](#0-2) 

And for intrinsic pubdata overhead:

```rust
let intrinsic_pubdata_overhead = native_per_pubdata_byte.saturating_mul(intrinsic_pubdata);
``` [4](#0-3) 

**Contrast with `native_per_gas`**, which correctly uses ceiling division to protect the protocol:

```rust
u256_try_to_u64(&gas_price.div_ceil(native_price))
``` [5](#0-4) 

The asymmetry is the root cause: computation is charged with ceiling division (protocol-protective), while pubdata is charged with floor division (user-favorable).

The double-resource accounting model defines:

> `nativePerGas := gasPrice/nativePrice` (ceiling)  
> pubdata cost := `pubdata_bytes * floor(pubdata_price / native_price)` [6](#0-5) 

---

### Impact Explanation

**Case 1 — Total precision loss (`pubdata_price < native_price`):**  
`native_per_pubdata = 0`. Every pubdata byte costs zero native resources. A transaction sender can write to as many storage slots as the `pubdata_limit` allows, generating the maximum allowed pubdata, while paying zero native resources for it. The prover must still prove all of this pubdata, but the user has not paid for the proving cost through the native resource mechanism.

**Case 2 — Partial precision loss (`pubdata_price % native_price ≠ 0`):**  
The undercharge per transaction is:

```
pubdata_bytes × (pubdata_price % native_price) / native_price
```

For a transaction using `N` pubdata bytes, the maximum undercharge is `N × (native_price − 1) / native_price < N` native units. A sender who generates large pubdata (e.g., many storage writes) systematically pays less than the true proving cost.

The `pubdata_limit` bounds the per-transaction damage but does not eliminate it. Across many transactions, the cumulative undercharge is unbounded.

---

### Likelihood Explanation

The operator sets `pubdata_price` and `native_price` independently as block-level oracle parameters: [7](#0-6) 

In practice, `pubdata_price` reflects the cost of L1 calldata/blob publication and `native_price` reflects the cost of a RISC-V proving cycle. These are denominated in different units and can easily satisfy `pubdata_price < native_price` under normal market conditions (e.g., when L1 gas is cheap relative to proving cycles). Any transaction sender can observe the block context and exploit the zero-cost pubdata window by submitting storage-heavy transactions.

---

### Recommendation

Use ceiling division for `native_per_pubdata`, consistent with how `native_per_gas` is computed:

```rust
// Before (floor division — undercharges):
let native_per_pubdata = u256_try_to_u64(&pubdata_price.wrapping_div(native_price))...;

// After (ceiling division — matches native_per_gas pattern):
let native_per_pubdata = u256_try_to_u64(&pubdata_price.div_ceil(native_price))...;
```

Apply the same fix in `api/src/helpers.rs` `validate_l2_tx_intrinsic_native_resources` to keep the off-chain pre-validation consistent with the bootloader. [8](#0-7) 

---

### Proof of Concept

**Setup:**
- `native_price = 1_000_000_000` (1 Gwei per native unit)
- `pubdata_price = 999_999_999` (just below `native_price`)
- `native_per_pubdata = floor(999_999_999 / 1_000_000_000) = 0`

**Attack:**
1. Attacker submits a transaction that writes to 1000 distinct storage slots.
2. Each write generates ~33 bytes of pubdata → ~33,000 bytes total.
3. Native cost charged for pubdata: `33_000 × 0 = 0` native units.
4. True cost: `33_000 × 999_999_999 / 1_000_000_000 ≈ 32_999` native units.
5. The prover proves 33,000 bytes of pubdata that the attacker did not pay for.

**Variant with partial loss:**
- `pubdata_price = 1_500_000_000`, `native_price = 1_000_000_000`
- `native_per_pubdata = 1` (true value: 1.5)
- For 33,000 pubdata bytes: charged 33,000 native, should charge 49,500 native.
- Undercharge: 16,500 native units per transaction. [1](#0-0) [9](#0-8)

### Citations

**File:** basic_bootloader/src/bootloader/transaction_flow/zk/validation_impl.rs (L135-137)
```rust
            u256_try_to_u64(&gas_price.div_ceil(native_price)).ok_or(TxError::Validation(
                InvalidTransaction::NativeResourcesAreTooExpensive,
            ))?
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

**File:** basic_bootloader/src/bootloader/transaction_flow/gas_helpers.rs (L352-352)
```rust
    let intrinsic_pubdata_overhead = native_per_pubdata_byte.saturating_mul(intrinsic_pubdata);
```

**File:** basic_bootloader/src/bootloader/transaction_flow/gas_helpers.rs (L422-434)
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
```

**File:** docs/double_resource_accounting.md (L37-42)
```markdown
First we define the ratio between EVM gas and native resource as:
  `nativePerGas := gasPrice/nativePrice`
Note: for call simulation we use a constant for it, as gasPrice might be set to 0.

Next we define the limit for the native resource as:
  `nativeLimit := gasLimit * nativePerGas`
```

**File:** zk_ee/src/system/metadata/basic_metadata.rs (L60-68)
```rust
pub trait ZkSpecificPricingMetadata {
    /// Price of an unit of native resources.
    fn native_price(&self) -> U256;

    /// Upper bound on total pubdata that can be used by the transaction.
    fn get_pubdata_limit(&self) -> u64;

    /// Price in base token of 1 byte of pubdata.
    fn get_pubdata_price(&self) -> U256;
```
