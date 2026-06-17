### Title
Unvalidated Zero-Address Refund Recipient in L1→L2 Transactions Causes Permanent Fund Loss - (File: `basic_bootloader/src/bootloader/transaction_flow/zk/process_l1_transaction.rs`)

---

### Summary

The bootloader's `process_l1_transaction` function unconditionally mints refund tokens to whatever address is stored in `transaction.reserved[1]` (the refund recipient field) without checking whether it is `address(0)`. The `validate_structure()` function explicitly defers this check with a `// TODO: validate address?` comment. When `address(0)` is supplied as the refund recipient — which is the default when no recipient is set — all refunded gas fees and, on failure, the entire deposit minus the operator fee, are permanently burned.

---

### Finding Description

In `basic_bootloader/src/bootloader/transaction/abi_encoded/mod.rs`, the `validate_structure()` function performs structural validation of L1→L2 and upgrade transactions. For `reserved[1]` (the refund recipient), validation is explicitly skipped: [1](#0-0) 

The comment `// TODO: validate address?` confirms this is a known gap. No zero-address check is performed anywhere in the parsing or validation pipeline.

In `process_l1_transaction`, the refund recipient is read directly from `transaction.reserved[1].read()` and passed to `mint_base_token` without any guard: [2](#0-1) 

The helper `u256_to_b160_checked` only asserts that the value fits in 160 bits; it does not reject `B160::ZERO`: [3](#0-2) 

`mint_base_token` then calls `transfer_from_treasury`, which transfers tokens from the treasury to the supplied address — including `address(0)`: [4](#0-3) 

The two scenarios where funds are lost:

1. **Successful transaction:** The unused gas refund (`prepaid_fee - pay_to_operator`) is minted to `address(0)`.
2. **Failed transaction:** The entire deposit minus the operator fee (`total_deposited - pay_to_operator`) is minted to `address(0)`. [5](#0-4) 

The test infrastructure itself defaults `refund_recipient` to `address(0)` when none is set: [6](#0-5) 

And a regression test explicitly exercises the zero-address refund recipient path, confirming the bootloader accepts and processes it without error: [7](#0-6) 

---

### Impact Explanation

Any L1→L2 transaction that carries a nonzero refund amount and specifies `address(0)` as `reserved[1]` will have those tokens permanently burned. On a failed transaction, this includes the full bridged deposit minus the operator fee — potentially the entire ETH/base-token value the user intended to bridge. Tokens transferred to `address(0)` via `transfer_from_treasury` are irrecoverable; no key controls that address on L2.

**Vulnerability class:** Public funds-loss path.

---

### Likelihood Explanation

The likelihood is high for contract-originated L1→L2 transactions. Any L1 contract that submits a priority transaction without explicitly populating the refund recipient field will have it default to `address(0)`. This is the exact scenario described in the reference report: the L1 contract's address is not controllable on L2, so the natural fallback is `address(0)`. The `L1TxBuilder` test helper itself defaults to `address(0)` when `.refund_recipient()` is not called, demonstrating how easy it is to omit this field. [8](#0-7) 

---

### Recommendation

In `validate_structure()`, add a check that `reserved[1]` is not `B160::ZERO` for `L1_L2_TX_TYPE` and `UPGRADE_TX_TYPE` transactions that carry a nonzero deposit. Alternatively, add the check at the point of use in `process_l1_transaction` before calling `mint_base_token`:

```rust
// Before minting refund:
if to_refund_recipient > U256::ZERO {
    let refund_recipient = u256_to_b160_checked(transaction.reserved[1].read());
    if refund_recipient == B160::ZERO {
        return Err(internal_error!("Zero address refund recipient").into());
    }
    mint_base_token::<S, Config>(...)?;
}
```

The `// TODO: validate address?` comment in `validate_structure()` should be resolved to enforce a non-zero address for the refund recipient field. [1](#0-0) 

---

### Proof of Concept

1. An L1 contract calls the ZKsync bridge to submit an L1→L2 priority transaction, omitting the refund recipient (leaving `reserved[1] = 0`).
2. The transaction is encoded and submitted to the sequencer.
3. `AbiEncodedTransaction::try_from_buffer` parses `reserved[1]` as `U256::ZERO` and `validate_structure()` passes without error (the `TODO` branch is a no-op).
4. The transaction executes. Whether it succeeds or fails, `to_refund_recipient > U256::ZERO` is true (there is always unused gas or a deposit remainder).
5. `u256_to_b160_checked(U256::ZERO)` returns `B160::ZERO`.
6. `mint_base_token` calls `transfer_from_treasury(..., &B160::ZERO, ...)`, crediting `address(0)` with the refund amount.
7. The tokens are permanently inaccessible. The originating L1 contract receives nothing. [9](#0-8)

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

**File:** basic_bootloader/src/bootloader/transaction_flow/zk/process_l1_transaction.rs (L768-769)
```rust
    transfer_from_treasury::<S>(system, amount, to, resources, Config::SIMULATION)
}
```

**File:** zk_ee/src/utils/integer_utils.rs (L133-143)
```rust
pub fn u256_to_b160_checked(src: U256) -> B160 {
    assert!(src.as_limbs()[3] == 0 && src.as_limbs()[2] < (1u64 << 32));
    let mut result = B160::ZERO;
    unsafe {
        result.as_limbs_mut()[0] = src.as_limbs()[0];
        result.as_limbs_mut()[1] = src.as_limbs()[1];
        result.as_limbs_mut()[2] = src.as_limbs()[2];
    }

    result
}
```

**File:** tests/rig/src/utils/mod.rs (L403-414)
```rust
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
