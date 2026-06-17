### Title
Warm SSTORE Native Resource Overcharge Due to Ignored `is_warm_write` Flag - (File: `basic_system/src/system_implementation/system/mod.rs`)

### Summary
`EthereumLikeStorageAccessCostModel::charge_storage_write_extra` accepts `is_warm_write: bool` and correctly uses it for ergs (EVM gas) computation, but completely ignores it when computing the native resource cost. Every SSTORE — warm or cold — is charged the full cold-level native cost. The constant `WARM_STORAGE_WRITE_EXTRA_NATIVE_COST = 1000` is defined but never applied, causing warm writes to be overcharged by approximately 40× in native resources.

### Finding Description
In `charge_storage_write_extra`, the ergs branch correctly gates the cold-write surcharge on `is_warm_write`:

```rust
let total_cost =
    if is_warm_write == false { total_cost + 100 }
    else { total_cost };
```

But the native-cost branch unconditionally selects between cold constants based solely on `is_new_slot`, never consulting `is_warm_write`:

```rust
let native = if is_new_slot {
    R::Native::from_computational(COLD_NEW_STORAGE_WRITE_EXTRA_NATIVE_COST)
} else {
    R::Native::from_computational(COLD_EXISTING_STORAGE_WRITE_EXTRA_NATIVE_COST)
};
``` [1](#0-0) 

`COLD_EXISTING_STORAGE_WRITE_EXTRA_NATIVE_COST = native_with_delegations!(40_000, 0, 660)` while `WARM_STORAGE_WRITE_EXTRA_NATIVE_COST = 1000`. The warm constant is defined in `cost_constants.rs` but never referenced in the write-charging path. [2](#0-1) 

This function is called from `apply_write_impl` for every SSTORE, passing `is_warm_read.0` as `is_warm_write`: [3](#0-2) 

Subsequent writes to the same slot within a transaction (warm writes) are therefore charged ~40× more native resources than intended.

This is the direct analog of the reference bug: a boolean flag (`is_warm_write`) that should determine the charging behavior is passed in but silently ignored for the native cost branch — exactly as `isTokenPresent` was set to `true` regardless of the `!token` condition in the reference.

### Impact Explanation
Native resource exhaustion causes transaction failure — `resources.charge(...)` returns `Err` and the transaction is rejected. A transaction that performs many warm SSTOREs (e.g., a contract that writes to the same storage slot repeatedly — reentrancy guards, counters, accumulators) will exhaust its native resource budget far sooner than the EVM gas budget allows. This creates a divergence: the transaction succeeds under standard EVM semantics but fails in ZKsync OS with out-of-native-resources, constituting a **valid-execution unprovability** issue. The per-warm-write native cost is `WARM_STORAGE_READ_NATIVE_COST + COLD_EXISTING_STORAGE_WRITE_EXTRA_NATIVE_COST ≈ 4,000 + 40,000 = 44,000` instead of the intended `4,000 + 1,000 = 5,000`.

### Likelihood Explanation
Any EVM contract that writes to the same storage slot more than once per transaction triggers the overcharge. Common patterns include reentrancy guards (lock/unlock), counters, and multi-step state machines. An unprivileged attacker can deploy such a contract and call it to reliably reproduce the failure. No privileged access is required.

### Recommendation
Gate the native cost on `is_warm_write` in `charge_storage_write_extra`:

```rust
let native = if is_warm_write {
    R::Native::from_computational(WARM_STORAGE_WRITE_EXTRA_NATIVE_COST)
} else if is_new_slot {
    R::Native::from_computational(COLD_NEW_STORAGE_WRITE_EXTRA_NATIVE_COST)
} else {
    R::Native::from_computational(COLD_EXISTING_STORAGE_WRITE_EXTRA_NATIVE_COST)
};
```

### Proof of Concept
1. Deploy a contract with a function that writes to slot 0 N times: `for i in 0..N { sstore(0, i) }`.
2. Call the function with enough EVM gas to succeed (N × ~5,000 gas).
3. Observe that ZKsync OS fails the transaction with out-of-native-resources while EVM execution succeeds.
4. Root cause: each warm write (iterations 2..N) pays `COLD_EXISTING_STORAGE_WRITE_EXTRA_NATIVE_COST` (~40,000 native) instead of `WARM_STORAGE_WRITE_EXTRA_NATIVE_COST` (1,000 native), a ~40× overcharge per warm write. [4](#0-3) [5](#0-4)

### Citations

**File:** basic_system/src/system_implementation/system/mod.rs (L70-114)
```rust
    fn charge_storage_write_extra(
        &self,
        ee_type: ExecutionEnvironmentType,
        initial_value: &Bytes32,
        current_value: &Bytes32,
        new_value: &Bytes32,
        resources: &mut R,
        is_warm_write: bool,
        is_new_slot: bool,
    ) -> Result<(), SystemError> {
        let ergs = match ee_type {
            ExecutionEnvironmentType::NoEE => Ergs::empty(),
            ExecutionEnvironmentType::EVM => {
                let total_cost = if new_value == current_value {
                    0
                } else if current_value == initial_value {
                    if initial_value.is_zero() {
                        // we do not purge slots, so we use another indicator here
                        SSTORE_SET_EXTRA
                    } else {
                        SSTORE_RESET_EXTRA
                    }
                } else {
                    0
                };

                let total_cost =
                    // In EVM spec there's a discrepancy for cold read and cold write costs. Cold
                    // writes add another 100 from thin air.
                    if is_warm_write == false { total_cost + 100 }
                    else { total_cost };

                Ergs(total_cost * ERGS_PER_GAS)
            }
        };
        let native = if is_new_slot {
            R::Native::from_computational(
                crate::system_implementation::flat_storage_model::cost_constants::COLD_NEW_STORAGE_WRITE_EXTRA_NATIVE_COST,
            )
        } else {
            R::Native::from_computational(
          crate::system_implementation::flat_storage_model::cost_constants::COLD_EXISTING_STORAGE_WRITE_EXTRA_NATIVE_COST,)
        };
        resources.charge(&R::from_ergs_and_native(ergs, native))
    }
```

**File:** basic_system/src/system_implementation/flat_storage_model/cost_constants.rs (L13-22)
```rust
pub const WARM_STORAGE_READ_NATIVE_COST: u64 = 4000;
// Avg is ~10x smaller, maybe we can reduce it, but it depends on cache state.
pub const WARM_STORAGE_WRITE_EXTRA_NATIVE_COST: u64 = 1000;
// Estimation based on worst-case
pub const COLD_EXISTING_STORAGE_READ_NATIVE_COST: u64 = native_with_delegations!(100_000, 0, 1320);
pub const COLD_NEW_STORAGE_READ_NATIVE_COST: u64 = 2 * COLD_EXISTING_STORAGE_READ_NATIVE_COST;
pub const COLD_EXISTING_STORAGE_WRITE_EXTRA_NATIVE_COST: u64 =
    native_with_delegations!(40_000, 0, 660);
pub const COLD_NEW_STORAGE_WRITE_EXTRA_NATIVE_COST: u64 =
    native_with_delegations!(100_000, 0, 1300);
```

**File:** basic_system/src/system_implementation/caches/generic_pubdata_aware_plain_storage.rs (L262-271)
```rust
        let is_new_slot = addr_data.element_properties().is_new_element();
        self.resources_policy.charge_storage_write_extra(
            ee_type,
            &val_at_tx_start,
            val_current,
            new_value,
            resources,
            is_warm_read.0,
            is_new_slot,
        )?;
```
