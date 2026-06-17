### Title
Unvalidated `refund_recipient` Address in L1→L2 Transaction Processing Causes Permanent Base Token Loss - (`basic_bootloader/src/bootloader/transaction_flow/zk/process_l1_transaction.rs`)

---

### Summary

The ZKsync OS bootloader processes L1→L2 priority transactions and mints a gas refund to a `refund_recipient` address stored in `transaction.reserved[1]`. This address is never validated — the code itself contains a `// TODO: validate address?` comment acknowledging the gap. If the `refund_recipient` is set to `address(0)` or any other inaccessible address, the refund tokens are permanently lost. The test suite confirms this path is live: `test_treasury_based_token_distribution_regression` explicitly uses `refund_recipient = address(0)` and verifies that tokens are successfully transferred there.

---

### Finding Description

In `validate_structure()` of `AbiEncodedTransaction`, the `reserved[1]` field (the refund recipient) is explicitly skipped with a developer TODO:

```rust
// reserved[1] = refund recipient for l1 to l2 and upgrade txs
match tx_type {
    Self::L1_L2_TX_TYPE | Self::UPGRADE_TX_TYPE => {
        // TODO: validate address?
    }
    _ => unreachable!(),
}
``` [1](#0-0) 

Later, in `process_l1_transaction`, the refund recipient is extracted from this unvalidated field via `u256_to_b160_checked` — which only asserts the value fits in 160 bits, not that it is a valid or non-zero address — and tokens are immediately minted to it:

```rust
if to_refund_recipient > U256::ZERO {
    let refund_recipient = u256_to_b160_checked(transaction.reserved[1].read());
    mint_base_token::<S, Config>(
        system, system_functions, memories.reborrow(),
        &to_refund_recipient, &refund_recipient, ...
    )?;
}
``` [2](#0-1) 

`mint_base_token` calls `transfer_from_treasury`, which subtracts from the treasury and adds to `to` with no address validity check: [3](#0-2) 

`u256_to_b160_checked` only asserts the upper limbs are zero — it does not reject `address(0)` or system addresses: [4](#0-3) 

The test `test_treasury_based_token_distribution_regression` confirms that `refund_recipient = address(0)` is accepted and tokens are transferred there without error: [5](#0-4) 

---

### Impact Explanation

Any L1→L2 transaction that has unused gas (i.e., `gas_limit > gas_used`, which is the common case) will trigger a refund mint to `refund_recipient`. If this address is `address(0)` or any other address from which tokens cannot be recovered (e.g., a burn address, a precompile, or a system contract with no withdrawal mechanism), the refund amount — denominated in the chain's base token — is permanently lost. The treasury balance is reduced and the tokens are credited to an inaccessible account, with no recovery path.

---

### Likelihood Explanation

The `refund_recipient` is set by the L1 transaction submitter in the L1 bridge contract call. It is a common pattern for bridge UIs, relayers, or smart contract integrations to pass `address(0)` as a default or fallback refund recipient (as the test itself demonstrates). A bug in any L1-side bridge contract, a UI default, or a deliberate omission can result in this field being zero. Since L1→L2 transactions cannot be invalidated by the bootloader once submitted, there is no recovery mechanism.

---

### Recommendation

In `validate_structure()`, add a check that `reserved[1]` (the refund recipient) is a non-zero address for `L1_L2_TX_TYPE` and `UPGRADE_TX_TYPE`. Alternatively, add a fallback in `process_l1_transaction`: if `refund_recipient` is `address(0)`, redirect the refund to `transaction.from()` (the originator). This mirrors the pattern used by the original Stakehouse report's recommended fix — verify the address is valid before transferring funds to it. [1](#0-0) 

---

### Proof of Concept

1. Submit an L1→L2 priority transaction with:
   - `gas_limit = 100_000`
   - `gas_price = 1_000`
   - `refund_recipient = address(0)` (stored in `reserved[1]`)
   - Any valid `to` and `value`

2. The bootloader executes the transaction. Suppose `gas_used = 21_000`. The refund is `(100_000 - 21_000) * 1_000 = 79_000_000` base token units.

3. `process_l1_transaction` reaches line 337: `let refund_recipient = u256_to_b160_checked(transaction.reserved[1].read())` → `B160::ZERO`.

4. `mint_base_token` is called with `to = address(0)`. `transfer_from_treasury` subtracts `79_000_000` from the treasury and adds it to `address(0)`.

5. The 79,000,000 base token units are permanently locked at `address(0)`. The treasury has been debited. No error is returned.

This is confirmed by the existing test `test_treasury_based_token_distribution_regression` which uses `refund_recipient = address(0)` and asserts the transfer succeeds. [6](#0-5)

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

**File:** basic_bootloader/src/bootloader/transaction_flow/zk/process_l1_transaction.rs (L336-359)
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
```

**File:** basic_bootloader/src/bootloader/transaction_flow/zk/process_l1_transaction.rs (L776-833)
```rust
pub fn transfer_from_treasury<'a, S: EthereumLikeTypes + 'a>(
    system: &mut System<S>,
    nominal_token_value: &U256,
    to: &B160,
    resources: &mut S::Resources,
    fee_payment_in_simulation: bool,
) -> Result<(), BootloaderSubsystemError>
where
    S::IO: IOSubsystemExt,
{
    system_log!(
        system,
        "Transferring {nominal_token_value:?} tokens from treasury to {to:?}\n"
    );

    let treasury_address = &system_hooks::addresses_constants::BASE_TOKEN_HOLDER_ADDRESS;

    let _ = system
        .io
        .update_account_nominal_token_balance(
            zk_ee::execution_environment_type::ExecutionEnvironmentType::EVM,
            resources,
            treasury_address,
            nominal_token_value,
            true, // true = subtract from balance
            fee_payment_in_simulation,
        )
        .map_err(|e| -> BootloaderSubsystemError {
            match e {
                SubsystemError::LeafUsage(balance_error) => {
                    system_log!(system, "Treasury transfer failed: {balance_error:?}");
                    interface_error!(BootloaderInterfaceError::TreasuryTransferFailed)
                }
                _ => wrap_error!(e),
            }
        })?;

    let _ = system
        .io
        .update_account_nominal_token_balance(
            zk_ee::execution_environment_type::ExecutionEnvironmentType::EVM,
            resources,
            to,
            nominal_token_value,
            false, // false = add to balance
            fee_payment_in_simulation,
        )
        .map_err(|e| -> BootloaderSubsystemError {
            match e {
                SubsystemError::LeafUsage(balance_error) => {
                    system_log!(system, "Error while minting: {balance_error:?}");
                    interface_error!(BootloaderInterfaceError::MintingBalanceOverflow)
                }
                _ => wrap_error!(e),
            }
        })?;

    Ok(())
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

**File:** tests/instances/transactions/src/lib.rs (L1843-1943)
```rust
    let refund_recipient = address!("0000000000000000000000000000000000000000"); // refund recipient (zero address)

    // Record initial treasury balance
    let treasury_initial_balance = tester.get_balance(&BASE_TOKEN_HOLDER_ADDRESS.into_alloy());

    // Record initial operator balance
    let operator_initial_balance = tester.get_balance(&coinbase);

    // Record initial recipient balance
    let recipient_initial_balance = tester.get_balance(&l1_recipient);

    // Record initial refund recipient balance
    let refund_recipient_initial_balance = tester.get_balance(&refund_recipient);

    // Create L1→L2 transaction with value transfer and fees
    let gas_price = 1000u64;
    let gas_limit = 100_000u64;
    let value_to_transfer = U256::from(1_000_000u64);

    // Credit L1 sender with enough balance for the value transfer
    tester = tester.with_balance(l1_sender, value_to_transfer);

    let l1_tx: ZKsyncTxEnvelope = L1TxBuilder::new()
        .from(l1_sender)
        .to(l1_recipient)
        .gas_price(gas_price.into())
        .gas_limit(gas_limit.into())
        .value(value_to_transfer)
        .build()
        .into();

    let block_context = BlockContext {
        coinbase: B160::from_alloy(coinbase),
        ..Default::default()
    };
    tester = tester.with_block_context(block_context);
    let output = tester.execute_block(vec![l1_tx]);

    // Verify transaction succeeded
    assert!(
        output.tx_results[0].is_ok(),
        "L1→L2 transaction should succeed, got: {:?}",
        output.tx_results[0]
    );

    let tx_result = output.tx_results[0].as_ref().unwrap();
    assert!(
        tx_result.is_success(),
        "L1→L2 transaction should be successful"
    );

    // Calculate expected fee payments
    let gas_used = tx_result.gas_used;
    let fee_paid_to_operator = U256::from(gas_used) * U256::from(gas_price);

    // Get final balances
    let treasury_final_balance = tester.get_balance(&BASE_TOKEN_HOLDER_ADDRESS.into_alloy());

    let operator_final_balance = tester.get_balance(&coinbase);

    let recipient_final_balance = tester.get_balance(&l1_recipient);

    let refund_recipient_final_balance = tester.get_balance(&refund_recipient);

    // Calculate total amount that should go to operator (fee + refund)
    // Refund recipient is 0 in this test
    let gas_limit = 100_000u64;
    let gas_refund = gas_limit - gas_used;
    let refund_amount = U256::from(gas_refund) * U256::from(gas_price);
    let total_to_operator = fee_paid_to_operator;
    let total_to_refund_recipient = refund_amount;

    // Verify treasury balance decreased by max fee (fees + refund)
    let treasury_decrease = treasury_initial_balance - treasury_final_balance;
    let expected_treasury_decrease = total_to_operator + total_to_refund_recipient;
    assert_eq!(
        treasury_decrease, expected_treasury_decrease,
        "Treasury should decrease by total operator payment plus refund and value transferred"
    );

    // Verify operator received total payment from treasury (fee + refund)
    let operator_increase = operator_final_balance - operator_initial_balance;
    assert_eq!(
        operator_increase, total_to_operator,
        "Operator should receive fee + refund from treasury"
    );

    // Verify recipient received value from treasury (not minted)
    let recipient_increase = recipient_final_balance - recipient_initial_balance;
    assert_eq!(
        recipient_increase, value_to_transfer,
        "Recipient should receive exact value amount from treasury"
    );

    // Verify refund recipient received value from treasury (not minted)
    let refund_recipient_increase =
        refund_recipient_final_balance - refund_recipient_initial_balance;
    assert_eq!(
        refund_recipient_increase, total_to_refund_recipient,
        "Refund recipient should receive correct refund amount from treasury"
    );
```
