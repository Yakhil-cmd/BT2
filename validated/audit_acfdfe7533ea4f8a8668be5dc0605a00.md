[1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5) [7](#0-6) [8](#0-7)

### Citations

**File:** aptos-move/aptos-vm/src/transaction_metadata.rs (L142-146)
```rust
            fee_payer: txn.authenticator_ref().fee_payer_address(),
            fee_payer_authentication_proof: txn
                .authenticator()
                .fee_payer_signer()
                .map(|signer| signer.authentication_proof()),
```

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

**File:** types/src/transaction/authenticator.rs (L179-224)
```rust
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

**File:** types/src/transaction/authenticator.rs (L317-331)
```rust
    pub fn fee_payer_signer(&self) -> Option<AccountAuthenticator> {
        match self {
            Self::Ed25519 { .. }
            | Self::MultiEd25519 { .. }
            | Self::MultiAgent { .. }
            | Self::SingleSender { .. } => None,
            Self::FeePayer {
                sender: _,
                secondary_signer_addresses: _,
                secondary_signers: _,
                fee_payer_address: _,
                fee_payer_signer,
            } => Some(fee_payer_signer.clone()),
        }
    }
```

**File:** aptos-move/aptos-vm/src/aptos_vm.rs (L1953-1992)
```rust
        let fee_payer_signer = if let Some(fee_payer) = transaction_data.fee_payer {
            Some(match &transaction_data.fee_payer_authentication_proof {
                Some(AuthenticationProof::Abstract {
                    function_info,
                    auth_data,
                }) => {
                    let enabled = match auth_data {
                        AbstractAuthenticationData::V1 { .. } => {
                            self.features().is_account_abstraction_enabled()
                        },
                        AbstractAuthenticationData::DerivableV1 { .. } => {
                            self.features().is_derivable_account_abstraction_enabled()
                        },
                    };
                    if enabled {
                        dispatchable_authenticate(
                            session,
                            gas_meter,
                            fee_payer,
                            function_info.clone(),
                            auth_data,
                            traversal_context,
                            module_storage,
                        )
                        .map_err(|mut vm_error| {
                            if vm_error.major_status() == OUT_OF_GAS {
                                vm_error
                                    .set_major_status(ACCOUNT_AUTHENTICATION_GAS_LIMIT_EXCEEDED);
                            }
                            vm_error.into_vm_status()
                        })
                    } else {
                        return Err(VMStatus::error(StatusCode::FEATURE_UNDER_GATING, None));
                    }
                },
                _ => Ok(serialized_signer(&fee_payer)),
            }?)
        } else {
            None
        };
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
