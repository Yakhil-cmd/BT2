[1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5) [7](#0-6) [8](#0-7)

### Citations

**File:** api/src/tests/simulation_test.rs (L464-515)
```rust
async fn bcs_simulate_fee_payer_transaction_without_gas_fee_check(context: &mut TestContext) {
    let alice = &mut context.gen_account();
    let bob = &mut context.gen_account();
    let txn = context.mint_user_account(alice).await;
    context.commit_block(&[txn]).await;

    let transfer_amount: u64 = SMALL_TRANSFER_AMOUNT;
    let txn = context.account_transfer_to(alice, bob.address(), transfer_amount);
    let mut raw_txn = txn.clone().into_raw_transaction();
    raw_txn.set_gas_unit_price(100);
    let txn = SignedTransaction::new_signed_transaction(
        raw_txn.clone(),
        TransactionAuthenticator::FeePayer {
            sender: AccountAuthenticator::NoAccountAuthenticator,
            secondary_signer_addresses: vec![],
            secondary_signers: vec![],
            fee_payer_address: AccountAddress::ONE,
            fee_payer_signer: AccountAuthenticator::NoAccountAuthenticator,
        },
    );
    let body = bcs::to_bytes(&txn).unwrap();
    let resp = context
        .expect_status_code(200)
        .post_bcs_txn("/transactions/simulate", body)
        .await;
    assert!(!resp[0]["success"].as_bool().unwrap(), "{}", pretty(&resp));
    assert!(
        resp[0]["vm_status"]
            .as_str()
            .unwrap()
            .contains("INSUFFICIENT_BALANCE_FOR_TRANSACTION_FEE"),
        "{}",
        pretty(&resp)
    );

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
        .expect_status_code(200)
        .post_bcs_txn("/transactions/simulate", body)
        .await;
    assert!(resp[0]["success"].as_bool().unwrap(), "{}", pretty(&resp));
}
```

**File:** api/src/tests/simulation_test.rs (L517-579)
```rust
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[rstest(
    use_txn_payload_v2_format,
    use_orderless_transactions,
    case(false, false),
    case(true, false),
    case(true, true)
)]
async fn test_bcs_simulate_automated_account_creation(
    use_txn_payload_v2_format: bool,
    use_orderless_transactions: bool,
) {
    let mut context = new_test_context_with_orderless_flags(
        current_function_name!(),
        use_txn_payload_v2_format,
        use_orderless_transactions,
    );
    let alice = &mut context.gen_account();
    let bob = &mut context.gen_account();

    let transfer_amount: u64 = 0;
    let txn = context.account_transfer_to(alice, bob.address(), transfer_amount);
    let mut raw_txn = txn.clone().into_raw_transaction();
    raw_txn.set_gas_unit_price(100);
    // Replace the authenticator with a NoAccountAuthenticator in the transaction.
    let txn = SignedTransaction::new_signed_transaction(
        raw_txn.clone(),
        TransactionAuthenticator::SingleSender {
            sender: AccountAuthenticator::NoAccountAuthenticator,
        },
    );

    let body = bcs::to_bytes(&txn).unwrap();

    let resp = context
        .expect_status_code(200)
        .post_bcs_txn("/transactions/simulate", body)
        .await;
    assert!(!resp[0]["success"].as_bool().unwrap(), "{}", pretty(&resp));
    assert!(
        resp[0]["vm_status"]
            .as_str()
            .unwrap()
            .contains("INSUFFICIENT_BALANCE_FOR_TRANSACTION_FEE"),
        "{}",
        pretty(&resp)
    );

    let txn =
        SignedTransaction::new_signed_transaction(raw_txn, TransactionAuthenticator::FeePayer {
            sender: AccountAuthenticator::NoAccountAuthenticator,
            secondary_signer_addresses: vec![],
            secondary_signers: vec![],
            fee_payer_address: AccountAddress::ZERO,
            fee_payer_signer: AccountAuthenticator::NoAccountAuthenticator,
        });
    let body = bcs::to_bytes(&txn).unwrap();
    let resp = context
        .expect_status_code(200)
        .post_bcs_txn("/transactions/simulate", body)
        .await;
    assert!(resp[0]["success"].as_bool().unwrap(), "{}", pretty(&resp));
}
```

**File:** api/src/tests/simulation_test.rs (L636-673)
```rust
async fn test_bcs_execute_fee_payer_transaction_no_authenticator_fail(
    use_txn_payload_v2_format: bool,
    use_orderless_transactions: bool,
) {
    let mut context = new_test_context_with_orderless_flags(
        current_function_name!(),
        use_txn_payload_v2_format,
        use_orderless_transactions,
    );
    let alice = &mut context.gen_account();
    let bob = &mut context.gen_account();
    let txn = context.mint_user_account(alice).await;
    context.commit_block(&[txn]).await;

    let transfer_amount: u64 = SMALL_TRANSFER_AMOUNT;
    let txn = context.account_transfer_to(alice, bob.address(), transfer_amount);
    let mut raw_txn = txn.clone().into_raw_transaction();
    raw_txn.set_gas_unit_price(100);
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
}
```

**File:** types/src/transaction/authenticator.rs (L160-224)
```rust
    pub fn verify(&self, raw_txn: &RawTransaction) -> Result<()> {
        let num_sigs: usize = self.sender().number_of_signatures()
            + self
                .secondary_signers()
                .iter()
                .map(|auth| auth.number_of_signatures())
                .sum::<usize>();
        if num_sigs > MAX_NUM_OF_SIGS {
            return Err(Error::new(AuthenticationError::MaxSignaturesExceeded));
        }
        // For encrypted transactions, signatures are verified over the encrypted form
        // (not the decrypted payload). Convert back to the encrypted variant for signing
        // message reconstruction.
        let raw_txn_for_signing = raw_txn.as_encrypted_variant();
        match self {
            Self::Ed25519 {
                public_key,
                signature,
            } => signature.verify(&raw_txn_for_signing, public_key),
            Self::FeePayer {
                sender,
                secondary_signer_addresses,
                secondary_signers,
                fee_payer_address,
                fee_payer_signer,
            } => {
                // In the fee payer model, the fee payer address can be optionally signed. We
                // realized when we designed the fee payer model, that we made it too restrictive
                // by requiring the signature over the fee payer address. So now we need to live in
                // a world where we support a multitude of different solutions. The modern approach
                // assumes that some may sign over the address and others will sign over the zero
                // address, so we verify both and only fail if the signature fails for either of
                // them. The legacy approach is to assume the address of the fee payer is signed
                // over.
                let mut to_verify = vec![sender];
                let _ = secondary_signers
                    .iter()
                    .map(|signer| to_verify.push(signer))
                    .collect::<Vec<_>>();

                let no_fee_payer_address_message = RawTransactionWithData::new_fee_payer(
                    raw_txn_for_signing.clone().into_owned(),
                    secondary_signer_addresses.clone(),
                    AccountAddress::ZERO,
                );

                let mut remaining = to_verify
                    .iter()
                    .filter(|verifier| verifier.verify(&no_fee_payer_address_message).is_err())
                    .collect::<Vec<_>>();

                remaining.push(&fee_payer_signer);

                let fee_payer_address_message = RawTransactionWithData::new_fee_payer(
                    raw_txn_for_signing.into_owned(),
                    secondary_signer_addresses.clone(),
                    *fee_payer_address,
                );

                for verifier in remaining {
                    verifier.verify(&fee_payer_address_message)?;
                }

                Ok(())
            },
```

**File:** types/src/transaction/authenticator.rs (L432-434)
```rust
                AccountAuthenticator::NoAccountAuthenticator => {
                    //  This case adds no single key authenticators to the vector.
                },
```

**File:** aptos-move/framework/aptos-framework/sources/transaction_validation.move (L778-791)
```text
        if (!skip_auth_key_check(is_simulation, &fee_payer_public_key_hash)) {
            let fee_payer_address = signer::address_of(&fee_payer);
            if (fee_payer_public_key_hash.is_some()) {
                assert!(
                    fee_payer_public_key_hash == option::some(account::get_authentication_key(fee_payer_address)),
                    error::invalid_argument(PROLOGUE_EINVALID_ACCOUNT_AUTH_KEY)
                );
            } else {
                assert!(
                    allow_missing_txn_authentication_key(fee_payer_address),
                    error::invalid_argument(PROLOGUE_EINVALID_ACCOUNT_AUTH_KEY)
                )
            };
        }
```

**File:** aptos-move/framework/aptos-framework/sources/transaction_validation.move (L901-917)
```text
                if (needs_fee_payer_auth_check) {
                    let fee_payer_address = signer::address_of(&fee_payer);
                    if (!skip_auth_key_check(is_simulation, &fee_payer_public_key_hash)) {
                        if (fee_payer_public_key_hash.is_some()) {
                            let fee_payer_public_key_hash = fee_payer_public_key_hash.destroy_some();
                            assert!(
                                fee_payer_public_key_hash == account::get_authentication_key(fee_payer_address),
                                error::invalid_argument(PROLOGUE_EINVALID_ACCOUNT_AUTH_KEY),
                            );
                        } else {
                            assert!(
                                allow_missing_txn_authentication_key(fee_payer_address),
                                error::invalid_argument(PROLOGUE_EINVALID_ACCOUNT_AUTH_KEY),
                            );
                        };
                    };
                };
```
