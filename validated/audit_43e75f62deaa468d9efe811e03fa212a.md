### Title
Missing Zero Address Check for `refund_recipient` in L1→L2 Transaction Processing Causes Permanent Fund Loss - (File: `basic_bootloader/src/bootloader/transaction/abi_encoded/mod.rs`)

---

### Summary

The `validate_structure` function for ABI-encoded L1→L2 and upgrade transactions contains an explicit `// TODO: validate address?` comment for the `refund_recipient` field (`reserved[1]`), confirming a known missing zero-address check. When `refund_recipient` is zero — which is the **default** in `L1TxBuilder` — the bootloader unconditionally mints the gas refund (or the entire deposit on failure) to the zero address, permanently burning those funds with no recovery path.

---

### Finding Description

**Step 1 — Validation is explicitly skipped.**

In `validate_structure`, the `reserved[1]` field (refund recipient) is acknowledged but left unvalidated:

```rust
// reserved[1] = refund recipient for l1 to l2 and upgrade txs
match tx_type {
    Self::L1_L2_TX_TYPE | Self::UPGRADE_TX_TYPE => {
        // TODO: validate address?
    }
    _ => unreachable!(),
}
``` [1](#0-0) 

**Step 2 — The unvalidated address is used directly for fund transfer.**

In `process_l1_transaction`, the refund recipient is read from `transaction.reserved[1]` with no zero-address guard, then passed directly to `mint_base_token`:

```rust
let refund_recipient = u256_to_b160_checked(transaction.reserved[1].read());
mint_base_token::<S, Config>(
    system, system_functions, memories.reborrow(),
    &to_refund_recipient,
    &refund_recipient,   // ← zero address accepted here
    ...
)?;
``` [2](#0-1) 

**Step 3 — The default value of `refund_recipient` is the zero address.**

`L1TxBuilder::build()` uses `unwrap_or_default()` for `refund_recipient`, which resolves to `Address::ZERO`:

```rust
refund_recipient: self.refund_recipient.unwrap_or_default(),
``` [3](#0-2) 

**Step 4 — Two distinct fund-loss paths exist.**

In `process_l1_transaction`, the amount sent to `refund_recipient` is:
- **On success**: `prepaid_fee - pay_to_operator` (unused gas refund)
- **On failure**: `total_deposited - pay_to_operator` (entire deposit minus fee) [4](#0-3) 

**Step 5 — Confirmed by existing test.**

A regression test explicitly uses zero address as `refund_recipient` and asserts that the refund tokens are credited to `address(0)`, confirming the system accepts and executes this path without error: [5](#0-4) [6](#0-5) 

---

### Impact Explanation

Any L1→L2 transaction (type `0x7F`) or upgrade transaction (type `0x7E`) that leaves `refund_recipient` at its default zero value will have its gas refund — or, on revert, its entire deposited value minus the operator fee — permanently minted to `address(0)`. These tokens are irrecoverable. The `// TODO: validate address?` comment in `validate_structure` confirms this is a known gap, not an intentional design choice. The impact is direct, permanent loss of user funds with no protocol-level recovery mechanism.

---

### Likelihood Explanation

The `L1TxBuilder` helper (the primary test and integration builder for L1→L2 transactions) defaults `refund_recipient` to `Address::ZERO` via `unwrap_or_default()`. Any caller that does not explicitly call `.refund_recipient(addr)` silently triggers the fund-loss path. The `// TODO: validate address?` comment in the production validation code confirms the check was never implemented. The path is reachable by any unprivileged L1 transaction sender.

---

### Recommendation

In `validate_structure` (`basic_bootloader/src/bootloader/transaction/abi_encoded/mod.rs`, lines 267–273), replace the `// TODO: validate address?` stub with an actual check that rejects transactions where `reserved[1]` decodes to the zero address:

```rust
Self::L1_L2_TX_TYPE | Self::UPGRADE_TX_TYPE => {
    let refund_recipient = self.reserved[1].validate_address().map_err(|_| ())?;
    if refund_recipient == B160::ZERO {
        return Err(());
    }
}
```

Alternatively, if zero-address refund recipients are intentionally allowed (e.g., to redirect the refund to `from`), the bootloader should substitute `transaction.from()` when `refund_recipient` is zero, rather than minting to `address(0)`.

---

### Proof of Concept

1. Submit an L1→L2 transaction (`type = 0x7F`) with `reserved[1] = 0` (zero address for `refund_recipient`) and `gas_limit` larger than the actual gas consumed.
2. The bootloader computes `to_refund_recipient = prepaid_fee - pay_to_operator > 0`.
3. Because `reserved[1]` is zero and no check exists, `mint_base_token` is called with `to = B160::ZERO`.
4. The refund tokens are credited to `address(0)` and are permanently inaccessible.

The existing test `test_treasury_based_token_distribution_regression` already demonstrates this exact behavior: it sets `refund_recipient = address(0x0000...0000)` and asserts that `refund_recipient_increase == total_to_refund_recipient`, confirming the tokens are sent to zero address without any error or revert. [1](#0-0) [7](#0-6) [8](#0-7)

### Citations

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

**File:** basic_bootloader/src/bootloader/transaction_flow/zk/process_l1_transaction.rs (L312-334)
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

**File:** tests/rig/src/utils/mod.rs (L396-415)
```rust
    pub fn build(self) -> ZKsyncTxEnvelope {
        ZKsyncL1Tx {
            from: self.from,
            to: self.to,
            max_fee_per_gas: self.gas_price,
            max_priority_fee_per_gas: self.gas_price,
            gas_limit: self.gas_limit,
            to_mint: self.to_mint.unwrap_or_else(|| {
                alloy::primitives::U256::from(self.gas_limit)
                    * alloy::primitives::U256::from(self.gas_price)
            }),
            input: self.input.into(),
            nonce: self.nonce,
            refund_recipient: self.refund_recipient.unwrap_or_default(),
            factory_deps: self.factory_deps,
            gas_per_pubdata_byte_limit: self.gas_per_pubdata_byte_limit,
            value: self.value,
        }
        .into()
    }
```

**File:** tests/instances/transactions/src/lib.rs (L1843-1843)
```rust
    let refund_recipient = address!("0000000000000000000000000000000000000000"); // refund recipient (zero address)
```

**File:** tests/instances/transactions/src/lib.rs (L1938-1943)
```rust
    let refund_recipient_increase =
        refund_recipient_final_balance - refund_recipient_initial_balance;
    assert_eq!(
        refund_recipient_increase, total_to_refund_recipient,
        "Refund recipient should receive correct refund amount from treasury"
    );
```
