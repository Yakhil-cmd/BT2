### Title
Missing Zero-Address Validation for `refund_recipient` in L1→L2 Transaction Processing Causes Permanent Base Token Loss - (`File: basic_bootloader/src/bootloader/transaction_flow/zk/process_l1_transaction.rs`)

---

### Summary

L1→L2 priority transactions carry a `refund_recipient` field (`reserved[1]`) that designates the address to receive unused-gas refunds. The bootloader extracts this field and mints base tokens to it without ever checking whether the address is `B160::ZERO`. A user who submits an L1→L2 transaction with `refund_recipient = address(0)` will have their entire gas-refund (or, on revert, the full deposit minus operator fee) permanently minted to the zero address and irrecoverably lost.

---

### Finding Description

In `process_l1_transaction.rs`, after the main transaction body executes, the bootloader computes `to_refund_recipient` and then reads the refund destination:

```rust
// line 337
let refund_recipient = u256_to_b160_checked(transaction.reserved[1].read());
mint_base_token::<S, Config>(
    system, system_functions, memories.reborrow(),
    &to_refund_recipient,
    &refund_recipient,          // ← can be B160::ZERO
    ...
)?;
```

`u256_to_b160_checked` only asserts that the upper 96 bits are zero (i.e., the value fits in 160 bits). It does **not** reject `B160::ZERO`. [1](#0-0) 

The structural validation function `validate_structure` explicitly skips this check with a `TODO` comment:

```rust
// reserved[1] = refund recipient for l1 to l2 and upgrade txs
match tx_type {
    Self::L1_L2_TX_TYPE | Self::UPGRADE_TX_TYPE => {
        // TODO: validate address?
    }
    ...
}
``` [2](#0-1) 

The helper `u256_to_b160_checked` confirms it only range-checks, not zero-checks: [3](#0-2) 

The existing regression test `test_treasury_based_token_distribution_regression` explicitly uses `address(0)` as `refund_recipient` and asserts that the refund amount is successfully credited to it — confirming the path is live and unguarded: [4](#0-3) [5](#0-4) 

---

### Impact Explanation

Base tokens (the L2 native token, ETH-equivalent) are permanently minted to `address(0)` and are unrecoverable. Two loss scenarios exist:

1. **Transaction succeeds**: The unused-gas refund (`(gas_limit − gas_used) × gas_price`) is minted to `address(0)`.
2. **Transaction reverts**: The entire deposit minus the operator fee (`total_deposited − pay_to_operator`) is minted to `address(0)`.

Both amounts originate from the treasury (`BASE_TOKEN_HOLDER_ADDRESS`) and represent real, circulating base tokens that are permanently destroyed. [6](#0-5) 

---

### Likelihood Explanation

Any unprivileged user submitting an L1→L2 priority transaction controls the `refund_recipient` field directly. The field is ABI-encoded in the transaction payload and is not validated on-chain before reaching ZKsync OS. Accidental zero-address submission is a well-known user error pattern (analogous to the 1inch FarmingPool report). Malicious actors can also deliberately set it to zero to burn their own refund, which could be used to grief the treasury accounting or to produce provably-lost funds for other protocol-level purposes. [7](#0-6) 

---

### Recommendation

Add a zero-address guard in `validate_structure` (removing the `TODO`) and/or at the point of use in `process_l1_transaction.rs`:

```rust
// In validate_structure (mod.rs ~line 269):
Self::L1_L2_TX_TYPE | Self::UPGRADE_TX_TYPE => {
    if self.reserved[1].read() == U256::ZERO {
        return Err(());
    }
}
```

Or, at the mint site in `process_l1_transaction.rs` before line 338, fall back to the transaction sender (`from`) when `refund_recipient` is zero — matching the behaviour of the original ZKsync Era bootloader:

```rust
let refund_recipient = {
    let r = u256_to_b160_checked(transaction.reserved[1].read());
    if r == B160::ZERO { transaction.from.read() } else { r }
};
``` [8](#0-7) 

---

### Proof of Concept

1. Submit an L1→L2 priority transaction with `refund_recipient = address(0)`, any non-zero `gas_limit`, and a `gas_price > 0`.
2. The transaction executes (success or revert).
3. In `process_l1_transaction`, `to_refund_recipient > 0` (unused gas × gas_price).
4. `refund_recipient = u256_to_b160_checked(0)` → `B160::ZERO`.
5. `mint_base_token(..., &to_refund_recipient, &B160::ZERO, ...)` is called.
6. `transfer_from_treasury` deducts from the treasury and credits `address(0)`.
7. The refund tokens are permanently lost.

The existing test `test_treasury_based_token_distribution_regression` in `tests/instances/transactions/src/lib.rs` already demonstrates this exact flow succeeding with `refund_recipient = address(0)` and asserts the balance of `address(0)` increases by the refund amount. [9](#0-8)

### Citations

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

**File:** tests/instances/transactions/src/lib.rs (L1827-1943)
```rust
/// Regression test for treasury-based token distribution
/// Tests that L1→L2 transactions correctly transfer fees and value from the treasury
/// instead of minting new tokens.
#[test]
fn test_treasury_based_token_distribution_regression() {
    use rig::system_hooks::addresses_constants::BASE_TOKEN_HOLDER_ADDRESS;

    let mut tester = TestingFramework::new();

    // Manually ensure treasury is funded for this test
    tester.mint_tokens_to_treasury();

    // Create L1 transaction sender
    let l1_sender = address!("1234000000000000000000000000000000000000");
    let l1_recipient = address!("5678000000000000000000000000000000000000");
    let coinbase = address!("1000000000000000000000000000000000000000"); // operator
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

**File:** tests/common/src/zksync_tx/l1_tx.rs (L14-32)
```rust
pub struct ZKsyncL1Tx {
    pub from: Address,
    pub to: Address,
    pub gas_limit: u128,
    pub gas_per_pubdata_byte_limit: u128,
    pub max_fee_per_gas: u128,
    pub max_priority_fee_per_gas: u128,
    pub nonce: u128,
    pub value: U256,
    /// The amount of base token that should be minted on L2 as the result of this transaction.
    pub to_mint: U256,
    /// The recipient of the refund for the transaction on L2. If the transaction fails, then this
    /// address will receive the `value` of this transaction.
    pub refund_recipient: Address,
    /// data: An unlimited size byte array specifying the input data of the message call.
    pub input: Bytes,
    /// The set of L2 bytecode hashes whose preimages were shown on L1.
    pub factory_deps: Vec<B256>,
}
```
