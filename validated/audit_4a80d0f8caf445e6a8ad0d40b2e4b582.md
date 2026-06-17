### Title
Unvalidated Zero `refund_recipient` in L1→L2 Transactions Causes Permanent Loss of Base Tokens - (`File: basic_bootloader/src/bootloader/transaction_flow/zk/process_l1_transaction.rs`)

---

### Summary

L1→L2 priority transactions (type `0x7F`) carry a `refund_recipient` address in `reserved[1]`. The bootloader mints the gas refund (and, on revert, the full deposit minus operator fee) unconditionally to this address. There is no validation that `reserved[1]` is non-zero. When it is zero — the default when the field is omitted — all refunded base tokens are minted to `address(0)` and permanently lost.

---

### Finding Description

In `process_l1_transaction.rs`, after computing the refund amount, the bootloader reads the refund recipient directly from the raw transaction field and mints to it:

```rust
// Line 336-343
if to_refund_recipient > U256::ZERO {
    let refund_recipient = u256_to_b160_checked(transaction.reserved[1].read());
    mint_base_token::<S, Config>(
        ...
        &to_refund_recipient,
        &refund_recipient,   // ← no zero-address check
        ...
    )
``` [1](#0-0) 

The structural validation function `validate_structure()` in `abi_encoded/mod.rs` explicitly defers this check with a `// TODO: validate address?` comment and performs no rejection:

```rust
// reserved[1] = refund recipient for l1 to l2 and upgrade txs
match tx_type {
    Self::L1_L2_TX_TYPE | Self::UPGRADE_TX_TYPE => {
        // TODO: validate address?
    }
    _ => unreachable!(),
}
``` [2](#0-1) 

The `refund_recipient` field defaults to `Address::default()` (zero) when not explicitly set. The `L1TxBuilder` in the test rig confirms this:

```rust
refund_recipient: self.refund_recipient.unwrap_or_default(),
``` [3](#0-2) 

Two loss scenarios exist:

**Scenario A — Successful transaction with unused gas:** `to_refund_recipient = prepaid_fee - pay_to_operator`. Any gas_limit > gas_used produces a non-zero refund minted to `address(0)`. [4](#0-3) 

**Scenario B — Reverted transaction:** `to_refund_recipient = total_deposited - pay_to_operator`. The entire deposit (minus operator fee) is minted to `address(0)`. [5](#0-4) 

---

### Impact Explanation

Base tokens minted to `address(0)` are permanently inaccessible. In the revert scenario, the loss equals `total_deposited - pay_to_operator`, which can be the full bridged deposit. This is a direct, irreversible loss of user funds processed by the ZKsync OS bootloader.

---

### Likelihood Explanation

**Medium-High.** The zero address is the Rust/Alloy default for `Address`. Any L1 bridge integration or direct L1→L2 transaction that omits `refund_recipient` triggers this. The existing test suite explicitly exercises the zero-address refund recipient path (line 1843 of `tests/instances/transactions/src/lib.rs`) and treats it as valid behavior, confirming the bootloader accepts and processes such transactions without error. [6](#0-5) 

---

### Recommendation

In `validate_structure()`, reject L1 and upgrade transactions where `reserved[1]` is zero:

```rust
Self::L1_L2_TX_TYPE | Self::UPGRADE_TX_TYPE => {
    if self.reserved[1].read().is_zero() {
        return Err(());
    }
    // optionally: validate upper 12 bytes are zero (valid address range)
}
```

Alternatively, fall back to `transaction.from` as the refund recipient when `reserved[1]` is zero, mirroring the Royco fix of defaulting to the sender.

---

### Proof of Concept

1. Submit an L1→L2 transaction (type `0x7F`) with `reserved[1] = 0` (zero `refund_recipient`), a non-zero `gas_limit`, and a `gas_price > 0`.
2. The transaction executes and succeeds, but `gas_used < gas_limit`.
3. `to_refund_recipient = gas_price * (gas_limit - gas_used) > 0`.
4. `refund_recipient = u256_to_b160_checked(0) = B160::ZERO`.
5. `mint_base_token(... &to_refund_recipient, &B160::ZERO ...)` is called — tokens are minted to `address(0)`.
6. The refund is permanently lost.

For the higher-impact revert path: submit the same transaction targeting a contract that reverts. `to_refund_recipient = total_deposited - pay_to_operator` (the full bridged deposit minus fee) is minted to `address(0)`. [7](#0-6)

### Citations

**File:** basic_bootloader/src/bootloader/transaction_flow/zk/process_l1_transaction.rs (L312-322)
```rust
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
```

**File:** basic_bootloader/src/bootloader/transaction_flow/zk/process_l1_transaction.rs (L323-334)
```rust
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

**File:** basic_bootloader/src/bootloader/transaction_flow/zk/process_l1_transaction.rs (L336-360)
```rust
    if to_refund_recipient > U256::ZERO {
        let refund_recipient = u256_to_b160_checked(transaction.reserved[1].read());
        mint_base_token::<S, Config>(
            system,
            system_functions,
            memories.reborrow(),
            &to_refund_recipient,
            &refund_recipient,
            l1_chain_id,
            &mut inf_resources,
            tracer,
            validator,
        )
        .map_err(|e| -> BootloaderSubsystemError {
            match e.root_cause() {
                RootCause::Runtime(RuntimeError::OutOfErgs(_)) => {
                    internal_error!("Out of ergs on infinite ergs").into()
                }
                RootCause::Runtime(RuntimeError::FatalRuntimeError(_)) => {
                    internal_error!("Out of native on infinite").into()
                }
                _ => e,
            }
        })?;
    }
```

**File:** basic_bootloader/src/bootloader/transaction/abi_encoded/mod.rs (L267-273)
```rust
        // reserved[1] = refund recipient for l1 to l2 and upgrade txs
        match tx_type {
            Self::L1_L2_TX_TYPE | Self::UPGRADE_TX_TYPE => {
                // TODO: validate address?
            }
            _ => unreachable!(),
        }
```

**File:** tests/rig/src/utils/mod.rs (L409-409)
```rust
            refund_recipient: self.refund_recipient.unwrap_or_default(),
```

**File:** tests/instances/transactions/src/lib.rs (L1843-1843)
```rust
    let refund_recipient = address!("0000000000000000000000000000000000000000"); // refund recipient (zero address)
```
