### Title
Hardcoded `L1_TX_NATIVE_PRICE = 10` vs. Operator-Provided `native_price` Creates Native Resource Accounting Mismatch for L1→L2 Transactions - (`basic_bootloader/src/bootloader/transaction_flow/zk/process_l1_transaction.rs`)

---

### Summary

L1→L2 priority transactions compute their native resource budget using a hardcoded constant `L1_TX_NATIVE_PRICE = 10`, while L2 transactions use the operator-provided `native_price` from block metadata. When the operator's `native_price` diverges significantly from 10 — which is realistic in production (tests show values like `911615`) — L1 transactions receive a disproportionately larger native resource budget per gas unit than L2 transactions for the same gas price. This is a direct analog to the external report's USD1/$1 vs. USDT oracle price mismatch: one class of transaction uses a hardcoded reference price while another uses the live oracle value, and the divergence creates an exploitable accounting asymmetry.

---

### Finding Description

**Vulnerability class**: Resource accounting bug / oracle IO mismatch — hardcoded price constant used instead of the live operator-provided price.

**L2 transactions** (`validation_impl.rs`, line 107):
```rust
let native_price = system.get_native_price(); // operator-provided, e.g. 911615
let native_per_gas = gas_price.div_ceil(native_price); // e.g. 91161500 / 911615 = 100
```

**L1→L2 transactions** (`process_l1_transaction.rs`, line 454):
```rust
let native_price = L1_TX_NATIVE_PRICE; // hardcoded = 10
let native_per_gas = gas_price.div_ceil(native_price); // e.g. 91161500 / 10 = 9_116_150
```

The `native_per_gas` ratio directly determines `native_prepaid_from_gas = native_per_gas * gas_limit`, which is the total native resource budget allocated to the transaction. A higher budget means the transaction can perform more proving-cycle-equivalent computation and write more pubdata before being reverted for resource exhaustion.

The `delta_gas` adjustment in `compute_gas_refund` (`refund_calculation.rs`, line 72) compounds the asymmetry:
```rust
let delta_gas = (native_used / native_per_gas) as i64 - (gas_used as i64);
if delta_gas > 0 { gas_used += delta_gas as u64; }
```
Because L1 transactions have a very high `native_per_gas`, `native_used / native_per_gas` rounds to near zero, so `delta_gas` is never positive — L1 transactions are never charged extra gas for native resource consumption. L2 transactions with a low `native_per_gas` (due to high `native_price`) regularly incur positive `delta_gas`, paying extra gas for the same native work.

The `native_per_pubdata` formula for L1 transactions (`process_l1_transaction.rs`, line 481) is also structurally different from L2:
- **L1**: `native_per_pubdata = gas_per_pubdata * (gas_price / 10)`
- **L2**: `native_per_pubdata = pubdata_price / native_price`

When `native_price >> 10`, the L1 formula yields a much higher `native_per_pubdata`, meaning L1 transactions have more withheld native resources available to pay for pubdata, allowing them to write more state diffs per gas unit than L2 transactions.

The TODO comment in `constants.rs` line 65 explicitly acknowledges the value is provisional:
```rust
// Default native price for L1->L2 transactions.
// TODO (EVM-1157): find a reasonable value for it.
pub const L1_TX_NATIVE_PRICE: U256 = U256::from_limbs([10, 0, 0, 0]);
```

---

### Impact Explanation

When `native_price >> L1_TX_NATIVE_PRICE`:

1. **Disproportionate native resource allocation**: An L1 transaction with `gas_price = 91_161_500` and `gas_limit = 72_000_000` receives `native_prepaid = 9_116_150 * 72_000_000 ≈ 656 billion` native units. An L2 transaction with identical parameters and `native_price = 911_615` receives `native_prepaid = 100 * 72_000_000 = 7.2 billion` — roughly 91,000× less.

2. **Block native budget exhaustion**: The block enforces a total native resource limit (evidenced by `BlockNativeLimitReached` error). An attacker submitting L1 transactions with high gas limits consumes the block's native budget at a rate far exceeding what they paid for relative to L2 users, crowding out L2 transactions.

3. **Asymmetric delta_gas charging**: L2 users are charged extra gas when native consumption exceeds EVM gas consumption; L1 users are not, even when consuming equivalent native resources.

4. **Pubdata budget asymmetry**: L1 transactions can write more pubdata per gas unit than L2 transactions, consuming the block's pubdata limit (`pubdata_limit` in `BlockMetadataFromOracle`) disproportionately.

---

### Likelihood Explanation

- The operator sets `native_price` dynamically to reflect proving costs. Test fixtures already use `native_price = 911_615` — 91,161× larger than `L1_TX_NATIVE_PRICE = 10`. In production, as proving infrastructure scales, `native_price` is expected to be orders of magnitude above 10.
- L1→L2 priority transactions are submitted by any unprivileged user on L1. No privileged access is required.
- The attacker pays L1 gas fees, but the cost is bounded by L1 gas prices, while the benefit (consuming L2 block native budget) scales with the ratio `native_price / L1_TX_NATIVE_PRICE`.
- The TODO comment confirms the value is not production-calibrated.

---

### Recommendation

1. **Use the operator-provided `native_price` for L1 transactions** where anti-censorship guarantees are not needed for the native resource ratio (the censorship concern is about gas price floors, not native price).
2. **If the hardcoded constant is intentional**, enforce an invariant that `L1_TX_NATIVE_PRICE` is kept within a bounded ratio of the operator's `native_price` (e.g., via a block-level check or operator configuration).
3. **Cap the effective `native_per_gas` for L1 transactions** to `min(gas_price / L1_TX_NATIVE_PRICE, gas_price / native_price * K)` for some safety multiplier `K`, preventing extreme divergence.
4. **Resolve EVM-1157** before production deployment with a calibrated value or a dynamic binding.

---

### Proof of Concept

**Setup**: Operator sets `native_price = 911_615` (as seen in `tests/instances/transactions/src/lib.rs:1793`), `eip1559_basefee = 91_161_500`.

**Attacker action**: Submit an L1 priority transaction with:
- `gas_price = 91_161_500`
- `gas_limit = 72_000_000` (block gas limit)
- `gas_per_pubdata = 800`

**L1 transaction resource allocation** (`process_l1_transaction.rs:454,469,481,490`):
```
native_price    = L1_TX_NATIVE_PRICE = 10
native_per_gas  = 91_161_500 / 10   = 9_116_150
native_per_pubdata = 800 * 9_116_150 = 7_292_920_000
native_prepaid  = 9_116_150 * 72_000_000 ≈ 656 billion
```

**Equivalent L2 transaction resource allocation** (`validation_impl.rs:107,135,142`):
```
native_price    = 911_615
native_per_gas  = 91_161_500 / 911_615 = 100
native_per_pubdata = pubdata_price / 911_615  (much smaller)
native_prepaid  = 100 * 72_000_000 = 7.2 billion
```

The L1 transaction receives ~91,000× more native resources than an equivalent L2 transaction. After `MAX_NATIVE_COMPUTATIONAL` caps the computational portion, the remainder is withheld for pubdata — allowing the L1 transaction to write vastly more pubdata than any L2 transaction at the same gas price. The block's `pubdata_limit` and native budget are consumed, and subsequent L2 transactions in the same block are rejected with `BlockNativeLimitReached` or `BlockPubdataLimitReached`.

**Key code references**: [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4)

### Citations

**File:** basic_bootloader/src/bootloader/constants.rs (L64-66)
```rust
// Default native price for L1->L2 transactions.
// TODO (EVM-1157): find a reasonable value for it.
pub const L1_TX_NATIVE_PRICE: U256 = U256::from_limbs([10, 0, 0, 0]);
```

**File:** basic_bootloader/src/bootloader/transaction_flow/zk/process_l1_transaction.rs (L453-496)
```rust
    // For L1->L2 txs, we use a constant native price to avoid censorship.
    let native_price = L1_TX_NATIVE_PRICE;
    let native_per_gas = if is_priority_op {
        if gas_price.is_zero() {
            if Config::SIMULATION {
                u256_try_to_u64(&system.get_eip1559_basefee().div_ceil(native_price))
                    .unwrap_or_else(|| {
                        system_log!(
                            system,
                            "Native per gas calculation for L1 tx overflows, using saturated arithmetic instead");
                        u64::MAX
                    })
            } else {
                FREE_L1_TX_NATIVE_PER_GAS
            }
        } else {
            u256_try_to_u64(&gas_price.div_ceil(native_price)).unwrap_or_else(|| {
                system_log!(
                    system,
                    "Native per gas calculation for L1 tx overflows, using saturated arithmetic instead");
                u64::MAX
            })
        }
    } else {
        // Upgrade txs are paid by the protocol, so we use a fixed native per gas
        FREE_L1_TX_NATIVE_PER_GAS
    };

    let native_per_pubdata = (gas_per_pubdata as u64)
        .checked_mul(native_per_gas)
        .unwrap_or_else(|| {
            system_log!(
                system,
                "Native per pubdata calculation for L1 tx overflows, using saturated arithmetic instead");
                u64::MAX
        });

    let native_prepaid_from_gas = native_per_gas.checked_mul(gas_limit)
        .unwrap_or_else(|| {
            system_log!(
                system,
                "Native prepaid from gas calculation for L1 tx overflows, using saturated arithmetic instead");
                u64::MAX
        });
```

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

**File:** basic_bootloader/src/bootloader/transaction_flow/refund_calculation.rs (L59-81)
```rust
    let full_native_limit = if cfg!(feature = "unlimited_native") || native_per_gas == 0 {
        u64::MAX - 1
    } else {
        gas_limit.saturating_mul(native_per_gas)
    };
    let native_used = full_native_limit.saturating_sub(resources.native().remaining().as_u64());

    #[cfg(not(feature = "unlimited_native"))]
    {
        // Adjust gas_used with difference with used native
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
        // TODO: return delta_gas to gas_used?
    }
```

**File:** docs/double_resource_accounting.md (L34-34)
```markdown
- `nativePrice` be a constant set by the operator, reflecting the "cost of processing a single cycle". Note: for L1->L2 transactions we use a code constant instead of one provided by operator.
```
