### Title
Unvalidated Zero `refund_recipient` in L1→L2 Transactions Permanently Burns Gas Refund Tokens — (`basic_bootloader/src/bootloader/transaction/abi_encoded/mod.rs`, `basic_bootloader/src/bootloader/transaction_flow/zk/process_l1_transaction.rs`)

---

### Summary

L1→L2 (priority) transactions carry a `refund_recipient` address in `reserved[1]`. The bootloader explicitly skips validation of this field (marked `// TODO: validate address?`) and unconditionally mints the unused-gas refund to whatever address is stored there. Because the field defaults to `address(0)` when not set by the submitter, any L1→L2 transaction that does not explicitly populate `refund_recipient` will have its entire gas refund permanently burned to the zero address.

---

### Finding Description

**Validation gap — `validate_structure`:**

In `basic_bootloader/src/bootloader/transaction/abi_encoded/mod.rs`, the `validate_structure` function explicitly skips zero-address validation for `reserved[1]`:

```rust
// reserved[1] = refund recipient for l1 to l2 and upgrade txs
match tx_type {
    Self::L1_L2_TX_TYPE | Self::UPGRADE_TX_TYPE => {
        // TODO: validate address?
    }
    _ => unreachable!(),
}
``` [1](#0-0) 

**Unconditional mint to unvalidated address — `process_l1_transaction`:**

In `process_l1_transaction.rs`, when `to_refund_recipient > U256::ZERO`, the bootloader reads `reserved[1]` directly and calls `mint_base_token` with no zero-address guard:

```rust
if to_refund_recipient > U256::ZERO {
    let refund_recipient = u256_to_b160_checked(transaction.reserved[1].read());
    mint_base_token::<S, Config>(
        system, system_functions, memories.reborrow(),
        &to_refund_recipient,
        &refund_recipient,   // ← can be B160::ZERO
        ...
    )?;
}
``` [2](#0-1) 

**Default value is zero — `L1TxBuilder`:**

The test/SDK builder defaults `refund_recipient` to `Address::default()` (= `address(0)`) when the caller omits it:

```rust
refund_recipient: self.refund_recipient.unwrap_or_default(),
``` [3](#0-2) 

**Protocol-level confirmation — regression test treats zero address as valid:**

The existing regression test explicitly uses `address(0)` as the refund recipient and asserts that the refund tokens are correctly credited there, confirming the protocol currently accepts and processes this silently:

```rust
let refund_recipient = address!("0000000000000000000000000000000000000000"); // refund recipient (zero address)
``` [4](#0-3) 

---

### Impact Explanation

When an L1→L2 transaction is submitted without an explicit `refund_recipient` (or with it set to `address(0)`), the bootloader computes the unused-gas refund amount (`gas_limit - gas_used`) × `gas_price`, then mints that value of base tokens to `address(0)`. Those tokens are permanently inaccessible — equivalent to burning them. The treasury balance is reduced by the full refund amount, the user receives nothing back, and no error is raised. The loss scales with `gas_limit`, `gas_price`, and how much gas goes unused. [5](#0-4) 

---

### Likelihood Explanation

- The `L1TxBuilder` (the primary SDK builder for L1→L2 transactions) defaults `refund_recipient` to `address(0)` when the caller does not call `.refund_recipient(...)`. Any integrator who omits this field silently burns their refund.
- The `// TODO: validate address?` comment in `validate_structure` confirms the developers themselves identified this as an unresolved gap.
- The existing regression test (`test_treasury_based_token_distribution_regression`) uses `address(0)` as the refund recipient and passes, meaning no downstream check catches this condition.
- No on-chain or off-chain mechanism warns the submitter that their refund will be burned. [1](#0-0) [6](#0-5) 

---

### Recommendation

Add a zero-address check in `validate_structure` for `reserved[1]` on L1→L2 and upgrade transactions:

```rust
Self::L1_L2_TX_TYPE | Self::UPGRADE_TX_TYPE => {
    // Reject zero refund recipient to prevent silent fund loss
    if self.reserved[1].read().is_zero() {
        return Err(());
    }
}
```

Alternatively, if a zero `refund_recipient` is intentionally allowed (e.g., to burn the refund), add an explicit guard in `process_l1_transaction` before calling `mint_base_token`, and document the behavior clearly. The `// TODO: validate address?` comment must be resolved either way. [1](#0-0) 

---

### Proof of Concept

1. Submit an L1→L2 transaction using `L1TxBuilder` without calling `.refund_recipient(...)`:
   ```rust
   let l1_tx = L1TxBuilder::new()
       .from(sender)
       .to(recipient)
       .gas_price(1000)
       .gas_limit(100_000)
       .value(U256::ZERO)
       .build(); // refund_recipient defaults to address(0)
   ```
2. The transaction executes and uses, say, 21,000 gas out of 100,000.
3. `to_refund_recipient = (100_000 - 21_000) × 1000 = 79_000_000` tokens.
4. `refund_recipient = u256_to_b160_checked(reserved[1]) = B160::ZERO`.
5. `mint_base_token(..., &79_000_000, &B160::ZERO, ...)` is called — 79,000,000 tokens are minted to `address(0)` and permanently lost.
6. The sender's balance is not restored; the treasury decreases by the full refund amount.

This is directly confirmed by the existing test `test_treasury_based_token_distribution_regression`, which uses `address(0)` as `refund_recipient` and asserts the refund is credited there without any error. [7](#0-6)

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

**File:** basic_bootloader/src/bootloader/transaction_flow/zk/process_l1_transaction.rs (L311-360)
```rust
    // Refund
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
    // Mint refund portion of the deposit to the refund recipient.
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

**File:** tests/rig/src/utils/mod.rs (L396-414)
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
```

**File:** tests/instances/transactions/src/lib.rs (L1843-1843)
```rust
    let refund_recipient = address!("0000000000000000000000000000000000000000"); // refund recipient (zero address)
```

**File:** tests/instances/transactions/src/lib.rs (L1937-1943)
```rust
    // Verify refund recipient received value from treasury (not minted)
    let refund_recipient_increase =
        refund_recipient_final_balance - refund_recipient_initial_balance;
    assert_eq!(
        refund_recipient_increase, total_to_refund_recipient,
        "Refund recipient should receive correct refund amount from treasury"
    );
```
