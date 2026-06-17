### Title
Missing Zero-Address Check on `refund_recipient` in L1→L2 Transaction Processing Causes Permanent Loss of Base Tokens - (File: `basic_bootloader/src/bootloader/transaction_flow/zk/process_l1_transaction.rs`)

### Summary
When an L1→L2 priority transaction is processed, the `refund_recipient` address is decoded directly from `transaction.reserved[1]` with no check that it is non-zero. If a user submits a transaction with `refund_recipient = address(0)` — which is the **default value** in the `L1TxBuilder` — the gas refund (and on failure, the entire deposit minus fees) is permanently minted to `address(0)`, burning those tokens irreversibly.

### Finding Description
In `process_l1_transaction.rs`, after computing the refund amount `to_refund_recipient`, the bootloader reads the refund recipient address and calls `mint_base_token` unconditionally:

```rust
// Line 337
let refund_recipient = u256_to_b160_checked(transaction.reserved[1].read());
mint_base_token::<S, Config>(
    system,
    system_functions,
    memories.reborrow(),
    &to_refund_recipient,
    &refund_recipient,   // <-- no check that this != address(0)
    ...
)
```

There is no guard of the form `require(refund_recipient != address(0))` before this call. The `transfer_from_treasury` function called inside `mint_base_token` also performs no zero-address check on its `to` parameter.

The default value for `refund_recipient` in `L1TxBuilder::build()` is `Address::default()` (i.e., `address(0)`):

```rust
// tests/rig/src/utils/mod.rs:409
refund_recipient: self.refund_recipient.unwrap_or_default(),
```

The existing regression test `test_treasury_based_token_distribution_regression` explicitly demonstrates this path: it sets `refund_recipient = address!("0000000000000000000000000000000000000000")` and verifies that the refund amount is successfully transferred to `address(0)`, confirming the tokens are burned with no error or revert.

### Impact Explanation
- **On transaction success**: the unused gas refund (`gas_limit - gas_used`) × `gas_price` in base tokens is permanently burned to `address(0)`.
- **On transaction failure**: the entire deposit minus the operator fee (`total_deposited - pay_to_operator`) is permanently burned to `address(0)`.

Both cases result in **direct, irreversible loss of base tokens** for the transaction submitter. The funds are deducted from the treasury and credited to `address(0)`, from which they can never be recovered.

### Likelihood Explanation
The `L1TxBuilder` default for `refund_recipient` is `address(0)`. Any bridge integration, wallet, or user that submits an L1→L2 priority transaction without explicitly setting a refund recipient will silently lose their gas refund. This is a realistic mistake, especially for automated bridge contracts that omit the field. The vulnerability requires no special privileges — any unprivileged L1 transaction sender can trigger it.

### Recommendation
Add a zero-address check before minting the refund. If `refund_recipient` is `address(0)`, either revert the transaction, redirect the refund to `transaction.from`, or skip the refund:

```rust
let refund_recipient = u256_to_b160_checked(transaction.reserved[1].read());
// Add this guard:
let refund_recipient = if refund_recipient == B160::ZERO {
    transaction.from.read()  // fall back to sender
} else {
    refund_recipient
};
```

Alternatively, enforce `refund_recipient != address(0)` as a hard validation error at the L1 transaction ingestion layer.

### Proof of Concept
1. Submit an L1→L2 priority transaction with `refund_recipient = address(0)` (the default) and `gas_limit` significantly larger than the gas actually consumed.
2. The bootloader executes `process_l1_transaction`.
3. At line 337, `refund_recipient` is decoded as `B160::ZERO`.
4. `mint_base_token` is called with `to = address(0)` and `amount = (gas_limit - gas_used) * gas_price`.
5. `transfer_from_treasury` subtracts the refund from the treasury and adds it to `address(0)`.
6. The submitter's gas refund is permanently lost.

The existing test `test_treasury_based_token_distribution_regression` (line 1843) already demonstrates this exact flow, confirming the tokens reach `address(0)` without any error. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3)

### Citations

**File:** basic_bootloader/src/bootloader/transaction_flow/zk/process_l1_transaction.rs (L335-360)
```rust
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

**File:** basic_bootloader/src/bootloader/transaction_flow/zk/process_l1_transaction.rs (L776-834)
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
