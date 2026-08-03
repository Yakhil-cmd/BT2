[1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4)

### Citations

**File:** types/src/transaction/authenticator.rs (L91-98)
```rust
    /// Optional Multi-agent transaction with a fee payer.
    FeePayer {
        sender: AccountAuthenticator,
        secondary_signer_addresses: Vec<AccountAddress>,
        secondary_signers: Vec<AccountAuthenticator>,
        fee_payer_address: AccountAddress,
        fee_payer_signer: AccountAuthenticator,
    },
```

**File:** aptos-move/e2e-move-tests/src/tests/fee_payer.rs (L433-469)
```rust
#[test]
fn test_prologue_same_address_fee_payer_rejects() {
    let mut h = MoveHarness::new();

    let sender = h.new_account_at(AccountAddress::from_hex_literal("0xa11ce").unwrap());
    let sender_balance = h.read_aptos_balance(sender.address());
    let sender_balance_seq_num = h.sequence_number(sender.address());

    let fee_payer = Account::new();
    let txn = TransactionBuilder::new(sender.clone())
        .payload(aptos_stdlib::aptos_account_set_allow_direct_coin_transfers(
            true,
        ))
        .sequence_number(sender_balance_seq_num)
        .max_gas_amount(1_000_000)
        .gas_unit_price(1)
        .raw()
        // The sender signs the open sponsored-transaction message with
        // fee payer address of 0x0.
        .sign_aa_transaction(
            Auth::Ed25519(&sender.privkey),
            vec![],
            vec![],
            // Attaches fee payer address to be the sender but sign the fee
            // payer leg with an unrelated key. Must be rejected by prologue.
            Some((*sender.address(), Auth::Ed25519(&fee_payer.privkey))),
        )
        .unwrap()
        .into_inner();

    let status = h.run(txn);
    assert!(matches!(
        status,
        TransactionStatus::Discard(StatusCode::INVALID_AUTH_KEY)
    ));
    assert_eq!(sender_balance, h.read_aptos_balance(sender.address()));
    assert_eq!(sender_balance_seq_num, h.sequence_number(sender.address()));
```

**File:** api/src/tests/simulation_test.rs (L654-672)
```rust
    let txn = SignedTransaction::new_signed_transaction(
        raw_txn.clone(),
        TransactionAuthenticator::FeePayer {
            sender: AccountAuthenticator::NoAccountAuthenticator,
            secondary_signer_addresses: vec![],
            secondary_signers: vec![],
            fee_payer_address: AccountAddress::ZERO,
            fee_payer_signer: AccountAuthenticator::NoAccountAuthenticator,
        },
    );
    let body = bcs::to_bytes(&txn).unwrap();
    let resp = context
        .expect_status_code(400)
        .post_bcs_txn("/transactions", body)
        .await;
    assert!(resp["message"]
        .as_str()
        .unwrap()
        .contains("INVALID_SIGNATURE"));
```

**File:** aptos-move/framework/aptos-framework/sources/transaction_validation.move (L629-630)
```text
    inline fun skip_gas_payment(is_simulation: bool, gas_payer: address): bool {
        is_simulation && gas_payer == @0x0
```

**File:** api/src/tests/transactions_test.rs (L907-942)
```rust
    let another_txn = another_raw_txn
        .clone()
        .sign_fee_payer(
            another_account.private_key(),
            vec![],
            vec![],
            AccountAddress::ZERO,
            fee_payer.private_key(),
        )
        .unwrap();

    let (sender, secondary_signer_addresses, secondary_signers) = match another_txn.authenticator()
    {
        TransactionAuthenticator::FeePayer {
            sender,
            secondary_signer_addresses,
            secondary_signers,
            fee_payer_address: _,
            fee_payer_signer: _,
        } => (sender, secondary_signer_addresses, secondary_signers),
        _ => panic!(
            "expecting TransactionAuthenticator::FeePayer, but got: {:?}",
            txn.authenticator()
        ),
    };

    let another_txn = another_raw_txn
        .clone()
        .sign_fee_payer(
            another_account.private_key(),
            vec![],
            vec![],
            fee_payer.address(),
            fee_payer.private_key(),
        )
        .unwrap();
```
