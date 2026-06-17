### Title
EIP-7702 Authorization List Intrinsic Gas Undercharges Empty Authority Accounts by `PER_AUTH_BASE_COST` - (`basic_bootloader/src/bootloader/transaction_flow/gas_helpers.rs`)

---

### Summary

The intrinsic gas formula for EIP-7702 authorization list entries pre-charges `NEWACCOUNT` (25,000 gas) per entry as the worst-case cost, then refunds `NEWACCOUNT - PER_AUTH_BASE_COST` (12,500 gas) when the authority is non-empty. For **empty** authority accounts (nonce == 0, no code, no balance), no refund is issued, so the net charge is `NEWACCOUNT = 25,000` gas. However, EIP-7702 specifies the cost for an empty authority is `PER_AUTH_BASE_COST + NEWACCOUNT = 37,500` gas. The implementation is missing the `PER_AUTH_BASE_COST = 12,500` gas component for empty authority accounts, causing a systematic undercharge that any unprivileged sender can exploit.

---

### Finding Description

In `calculate_tx_intrinsic_gas`, the EIP-7702 authorization list cost is computed as:

```rust
// EIP-7702 authorization list: per-authorization. We precharge the
// empty-account cost; when the authority turns out to be non-empty the
// delta (NEWACCOUNT - PER_AUTH_BASE_COST) is added back as a gas refund
// inside `validate_and_apply_delegation`.
intrinsic_gas = intrinsic_gas.saturating_add(
    authorization_list_num.saturating_mul(evm_interpreter::gas_constants::NEWACCOUNT),
);
``` [1](#0-0) 

`NEWACCOUNT = 25,000`. The comment states this is the "empty-account cost", but per EIP-7702 the correct worst-case cost for an empty authority is `PER_AUTH_BASE_COST + NEWACCOUNT = 12,500 + 25,000 = 37,500`.

Inside `validate_and_apply_delegation`, the function is called with infinite ergs (so the `NEWACCOUNT` charge there is a no-op on gas), and when the authority is **not** empty, a refund of `NEWACCOUNT - PER_AUTH_BASE_COST = 12,500` is issued:

```rust
if !is_empty {
    let ergs = Ergs(
        (evm_interpreter::gas_constants::NEWACCOUNT
            - evm_interpreter::gas_constants::PER_AUTH_BASE_COST)
            * ERGS_PER_GAS,
    );
    system
        .io
        .add_to_refund_counter(S::Resources::from_ergs(ergs))?
}
``` [2](#0-1) 

The resulting net gas cost per authorization entry is:

| Authority state | ZKsync OS charges | EIP-7702 requires | Delta |
|---|---|---|---|
| Non-empty | `25,000 − 12,500 = 12,500` | `12,500` | 0 (correct) |
| **Empty** | `25,000` | `37,500` | **−12,500 (undercharge)** |

The gas constants involved:

```rust
pub const NEWACCOUNT: u64 = 25000;
pub const PER_AUTH_BASE_COST: u64 = 12_500;
``` [3](#0-2) 

The authorization list processing is gated by `#[cfg(feature = "eip-7702")]` and is invoked during transaction validation:

```rust
intrinsic_resources.with_infinite_ergs(|inf_resources| {
    crate::bootloader::transaction::authorization_list::parse_authorization_list_and_apply_delegations(
        system,
        inf_resources,
        authorization_list,
    )
})?;
``` [4](#0-3) 

The `evm_refund` from the refund counter is then applied in `compute_gas_refund`, capped at 1/5 of gas used per EIP-3529:

```rust
let evm_refund = {
    let full_refund_ergs = system.io.get_refund_counter().ergs();
    let full_refund_gas = full_refund_ergs.0.div_floor(ERGS_PER_GAS);
    let max_refund = gas_used / 5;
    core::cmp::min(full_refund_gas, max_refund)
};
gas_used -= evm_refund;
``` [5](#0-4) 

---

### Impact Explanation

An attacker submitting an EIP-7702 transaction with `N` empty authority accounts (fresh key pairs, nonce == 0, no code, no balance) pays `N × 12,500` less gas than EIP-7702 requires. With a 30 M gas block limit, up to ~1,200 authorization entries are possible, saving up to **15 M gas** per transaction. This:

1. Allows more EVM computation than the gas limit should permit (resource accounting bug).
2. Causes the operator to receive less fee than owed.
3. Enables a sustained underpriced-computation attack if the `eip-7702` feature is active.

---

### Likelihood Explanation

Any unprivileged sender can exploit this by generating fresh secp256k1 key pairs (empty accounts by definition) and including them as authorization entries. No privileged access, oracle manipulation, or governance control is required. The attack is deterministic and repeatable every block.

---

### Recommendation

Change the intrinsic pre-charge to the true worst-case cost `PER_AUTH_BASE_COST + NEWACCOUNT` per authorization entry, and adjust the refund to `NEWACCOUNT` (not `NEWACCOUNT - PER_AUTH_BASE_COST`) when the authority is non-empty:

```rust
// gas_helpers.rs – intrinsic pre-charge
intrinsic_gas = intrinsic_gas.saturating_add(
    authorization_list_num.saturating_mul(
        evm_interpreter::gas_constants::PER_AUTH_BASE_COST
            + evm_interpreter::gas_constants::NEWACCOUNT,
    ),
);

// authorization_list.rs – refund when non-empty
if !is_empty {
    let ergs = Ergs(evm_interpreter::gas_constants::NEWACCOUNT * ERGS_PER_GAS);
    system.io.add_to_refund_counter(S::Resources::from_ergs(ergs))?
}
```

Net cost after fix:
- Empty authority: `PER_AUTH_BASE_COST + NEWACCOUNT = 37,500` ✓
- Non-empty authority: `(PER_AUTH_BASE_COST + NEWACCOUNT) − NEWACCOUNT = PER_AUTH_BASE_COST = 12,500` ✓

---

### Proof of Concept

1. Generate `N` fresh secp256k1 key pairs. Each corresponding address has nonce == 0, no code, no balance — satisfying the EIP-7702 "empty" condition.
2. For each key pair, sign an authorization tuple `(chain_id, delegate_address, nonce=0)`.
3. Submit an EIP-7702 transaction with all `N` authorization entries.
4. The bootloader charges `N × NEWACCOUNT = N × 25,000` gas for the authorization list.
5. EIP-7702 requires `N × (PER_AUTH_BASE_COST + NEWACCOUNT) = N × 37,500` gas.
6. The attacker saves `N × 12,500` gas, which can be redirected to additional EVM execution within the same transaction.

### Citations

**File:** basic_bootloader/src/bootloader/transaction_flow/gas_helpers.rs (L291-297)
```rust
    // EIP-7702 authorization list: per-authorization. We precharge the
    // empty-account cost; when the authority turns out to be non-empty the
    // delta (NEWACCOUNT - PER_AUTH_BASE_COST) is added back as a gas refund
    // inside `validate_and_apply_delegation`.
    intrinsic_gas = intrinsic_gas.saturating_add(
        authorization_list_num.saturating_mul(evm_interpreter::gas_constants::NEWACCOUNT),
    );
```

**File:** basic_bootloader/src/bootloader/transaction/authorization_list.rs (L165-174)
```rust
    if !is_empty {
        let ergs = Ergs(
            (evm_interpreter::gas_constants::NEWACCOUNT
                - evm_interpreter::gas_constants::PER_AUTH_BASE_COST)
                * ERGS_PER_GAS,
        );
        system
            .io
            .add_to_refund_counter(S::Resources::from_ergs(ergs))?
    }
```

**File:** evm_interpreter/src/gas_constants.rs (L13-54)
```rust
pub const NEWACCOUNT: u64 = 25000;
pub const EXP: u64 = 10;
pub const MEMORY: u64 = 3;
pub const LOG: u64 = 375;
pub const LOGDATA: u64 = 8;
pub const LOGTOPIC: u64 = 375;
pub const SHA3: u64 = 30;
pub const SHA3WORD: u64 = 6;
pub const COPY: u64 = 3;
pub const BLOCKHASH: u64 = 20;
pub const CODEDEPOSIT: u64 = 200;
pub const BLOBHASH: u64 = 3;

// SSTORE write extras.
pub const REFUND_SSTORE_CLEARS: i64 = 15000;
pub const SSTORE_SET_EXTRA: u64 = 19900;
pub const SSTORE_RESET_EXTRA: u64 = 2800;

pub const TRANSACTION_ZERO_DATA: u64 = 4;
pub const TRANSACTION_NON_ZERO_DATA_INIT: u64 = 16;
pub const TRANSACTION_NON_ZERO_DATA_FRONTIER: u64 = 68;

// berlin eip2929 constants
pub const ACCESS_LIST_ADDRESS: u64 = 2400;
pub const ACCESS_LIST_STORAGE_KEY: u64 = 1900;
pub const COLD_SLOAD_COST: u64 = 2100;
pub const COLD_ACCOUNT_ACCESS_COST: u64 = 2600;
pub const WARM_STORAGE_READ_COST: u64 = 100;

/// EIP-3860 : Limit and meter initcode
pub const INITCODE_WORD_COST: u64 = 2;

pub const CALL_STIPEND: u64 = 2300;

pub const ADDRESS_ACCESS_COST_COLD: u64 = 2600;
pub const ADDRESS_ACCESS_COST_WARM: u64 = 100;

pub const TSTORE: u64 = 100;
pub const TLOAD: u64 = 100;
pub const SELFBALANCE: u64 = 5;

pub const PER_AUTH_BASE_COST: u64 = 12_500;
```

**File:** basic_bootloader/src/bootloader/transaction_flow/zk/validation_impl.rs (L423-435)
```rust
    #[cfg(feature = "eip-7702")]
    {
        if let Some(authorization_list) = transaction.authorization_list() {
            // Same as for the access list: gas is included in the intrinsic
            // gas above, so we are only charging native
            intrinsic_resources.with_infinite_ergs(|inf_resources| {
                crate::bootloader::transaction::authorization_list::parse_authorization_list_and_apply_delegations(
                    system,
                    inf_resources,
                    authorization_list,
                )
            })?;
        }
```

**File:** basic_bootloader/src/bootloader/transaction_flow/refund_calculation.rs (L39-48)
```rust
    let evm_refund = {
        let full_refund_ergs = system.io.get_refund_counter().ergs();
        let full_refund_gas = full_refund_ergs.0.div_floor(ERGS_PER_GAS);
        let max_refund = gas_used / 5;
        core::cmp::min(full_refund_gas, max_refund)
    };

    system_log!(system, "Gas refund from refund counters = {evm_refund}\n");

    gas_used -= evm_refund;
```
