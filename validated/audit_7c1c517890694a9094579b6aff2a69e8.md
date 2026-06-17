### Title
EIP-7702 Authorization Intrinsic Pubdata Overcharge: Failed Delegations Still Consume Full Per-Authorization Pubdata Budget - (`basic_bootloader/src/bootloader/transaction_flow/gas_helpers.rs`)

### Summary

For EIP-7702 (type-4) transactions, the bootloader pre-charges native resources for pubdata based on the **worst-case** assumption that every authorization entry in the list will result in a successful delegation write. When authorization entries fail (wrong chain ID, nonce mismatch, bad signature, authority is a contract, etc.), no state change occurs for those entries, yet the full `L2_TX_INTRINSIC_PUBDATA_PER_AUTHORIZATION` (80 bytes) is still consumed from the user's native resource budget with no refund mechanism. This is the direct analog of the reported "open fee is overcharged based on desired amount rather than actual amount used."

### Finding Description

In `create_resources_for_tx` in `basic_bootloader/src/bootloader/transaction_flow/gas_helpers.rs`, the intrinsic pubdata overhead is computed and **immediately subtracted** from the user's native limit before execution begins:

```rust
// Charge intrinsic pubdata
let intrinsic_pubdata_overhead = native_per_pubdata_byte.saturating_mul(intrinsic_pubdata);
let native_limit = match native_limit.checked_sub(intrinsic_pubdata_overhead) { ... };
```

The `intrinsic_pubdata` value for an EIP-7702 transaction is:

```rust
pub fn calculate_l2_tx_intrinsic_pubdata(authorization_list_num: u64, is_service: bool) -> u64 {
    let mut intrinsic_pubdata = L2_TX_INTRINSIC_PUBDATA;
    intrinsic_pubdata = intrinsic_pubdata.saturating_add(
        authorization_list_num.saturating_mul(L2_TX_INTRINSIC_PUBDATA_PER_AUTHORIZATION),
    );
    intrinsic_pubdata
}
```

`L2_TX_INTRINSIC_PUBDATA_PER_AUTHORIZATION` = 80 bytes, representing the full state diff for a successful delegation write (key + account metadata + versioning + nonce + balance + code fields).

However, `validate_and_apply_delegation` in `basic_bootloader/src/bootloader/transaction/authorization_list.rs` returns `Ok(false)` for many failure conditions (wrong chain ID, nonce overflow, bad s-value, ecrecover failure, authority is a contract, nonce mismatch) **without writing any state**. When a delegation fails, the actual pubdata produced for that entry is **zero**, but the user has already been charged 80 bytes worth of native resources for it.

The `before_refund` function in `basic_bootloader/src/bootloader/transaction_flow/zk/mod.rs` adds `intrinsic_pubdata` (which includes the full per-authorization budget) to `total_pubdata_used` regardless of how many delegations actually succeeded:

```rust
let intrinsic_pubdata = calculate_l2_tx_intrinsic_pubdata(
    context.authorization_list_num,
    transaction.is_service(),
);
// ...
(pubdata_used + intrinsic_pubdata, to_charge_for_pubdata)
```

The codebase itself acknowledges this overcharge for the **computational native** dimension (the `verify_intrinsic_native` check explicitly skips the overcharging assertion when `authorization_list_num > 0`), but there is no analogous correction for the **pubdata native** dimension.

### Impact Explanation

A user submitting an EIP-7702 transaction with N authorization entries where some or all fail validation is charged `N × 80 × native_per_pubdata_byte` native resources for pubdata that is never actually written. This native resource is deducted from the user's budget at transaction start and never returned. The excess charge translates directly into excess gas consumed (via the `delta_gas` mechanism in `compute_gas_refund`), meaning the user pays more ETH in fees than the actual on-chain work warrants. The overcharge scales linearly with the number of failed authorization entries and with the `pubdata_price` / `native_price` ratio set by the operator.

**Concrete scenario:** A user submits a type-4 transaction with 10 authorization entries, all of which fail (e.g., all have wrong chain IDs). The user is charged `10 × 80 = 800` bytes of intrinsic pubdata that produces zero actual state diffs. At a `native_per_pubdata` of 1000, this is 800,000 extra native units consumed, which feeds back into `gas_used` via `delta_gas`, causing the user to pay for ~800,000 / `native_per_gas` extra gas.

### Likelihood Explanation

EIP-7702 is a live feature (gated by `#[cfg(feature = "eip-7702")]`). Any user or contract that submits a type-4 transaction where one or more authorization entries fail for any reason (wrong chain ID, stale nonce, bad signature, authority is already a contract) will trigger this overcharge. This is reachable by any unprivileged transaction sender with no special access required. The attacker-controlled entry path is simply submitting an EIP-7702 transaction with intentionally or accidentally invalid authorization entries.

### Recommendation

Track the number of **successful** delegations during `parse_authorization_list_and_apply_delegations` and use that count (rather than the total `authorization_list_num`) when computing the intrinsic pubdata charge in `before_refund`. Alternatively, charge pubdata for authorizations post-execution based on actual state diffs produced, consistent with how execution pubdata is handled.

### Proof of Concept

1. Submit an EIP-7702 (type-4) transaction with `authorization_list_num = 10`, where all 10 entries have `chain_id` set to a value that does not match the current chain and is not zero.
2. In `validate_and_apply_delegation`, each entry hits the check at line 108 and returns `Ok(false)` — no state is written.
3. In `create_resources_for_tx`, `intrinsic_pubdata = L2_TX_INTRINSIC_PUBDATA + 10 × 80 = base + 800` bytes is pre-charged from the native limit.
4. In `before_refund`, `intrinsic_pubdata` is again computed as `base + 800` and added to `total_pubdata_used`, even though actual pubdata from delegations is 0.
5. `compute_gas_refund` computes `native_used` including this phantom 800-byte charge, and `delta_gas` inflates `gas_used` accordingly.
6. The user pays for 800 bytes of pubdata that was never written to the settlement layer. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5) [7](#0-6)

### Citations

**File:** basic_bootloader/src/bootloader/transaction_flow/gas_helpers.rs (L302-314)
```rust
pub fn calculate_l2_tx_intrinsic_pubdata(authorization_list_num: u64, is_service: bool) -> u64 {
    if is_service {
        // there is no intrinsic pubdata for service txs
        return 0;
    }
    let mut intrinsic_pubdata = L2_TX_INTRINSIC_PUBDATA;

    intrinsic_pubdata = intrinsic_pubdata.saturating_add(
        authorization_list_num.saturating_mul(L2_TX_INTRINSIC_PUBDATA_PER_AUTHORIZATION),
    );

    intrinsic_pubdata
}
```

**File:** basic_bootloader/src/bootloader/transaction_flow/gas_helpers.rs (L351-359)
```rust
    // Charge intrinsic pubdata
    let intrinsic_pubdata_overhead = native_per_pubdata_byte.saturating_mul(intrinsic_pubdata);
    let native_limit = match native_limit.checked_sub(intrinsic_pubdata_overhead) {
        Some(val) => val,
        None => P::handle_arithmetic_error(
            system,
            P::native_underflow_error("subtracting pubdata overhead"),
        )?,
    };
```

**File:** basic_bootloader/src/bootloader/constants.rs (L210-220)
```rust
/// L2 tx authorization intrinsic pubdata.
pub const L2_TX_INTRINSIC_PUBDATA_PER_AUTHORIZATION: u64 = // Full diff compression:
    32 + // key
    1 + // account metadata
    8 + // versioning data
    2 + // nonce
    1 + // balance
    4 + // unpadded code length
    4 + // artifacts length
    24 + // padded bytecode
    4; // observable length
```

**File:** basic_bootloader/src/bootloader/transaction/authorization_list.rs (L107-114)
```rust
    // 1. Check chain id
    if !auth_chain_id.is_zero() && auth_chain_id != &U256::from(chain_id) {
        return Ok(false);
    }
    // 2. Check for nonce overflow
    if auth_nonce == u64::MAX {
        return Ok(false);
    }
```

**File:** basic_bootloader/src/bootloader/transaction_flow/zk/mod.rs (L401-412)
```rust
        let intrinsic_pubdata = calculate_l2_tx_intrinsic_pubdata(
            context.authorization_list_num,
            transaction.is_service(),
        );

        // Pubdata for validation has been charged already,
        // we charge for the rest now.
        let (total_pubdata_used, to_charge_for_pubdata) = match pubdata_info {
            Some(CachedPubdataInfo {
                pubdata_used,
                to_charge_for_pubdata,
            }) => (pubdata_used + intrinsic_pubdata, to_charge_for_pubdata),
```

**File:** basic_bootloader/src/bootloader/transaction_flow/zk/mod.rs (L935-946)
```rust
        // Skip the overcharging check when authorization-list entries are
        // present: failed auths (bad sig, wrong chain id, nonce overflow)
        // consume only PER_AUTH_NATIVE_COMPUTATIONAL_OVERHEAD while the
        // formula budgets worst-case success cost per entry.
        if context.authorization_list_num == 0 {
            assert!(
                formula <= actual_used * 2,
                "intrinsic computational native formula ({}) is overcharging more than twice compared to actual consumption ({})",
                formula,
                actual_used
            );
        }
```

**File:** basic_bootloader/src/bootloader/transaction_flow/refund_calculation.rs (L62-80)
```rust
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
```
