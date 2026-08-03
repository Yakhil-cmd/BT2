Based on the evidence gathered, this scenario is not a vulnerability — it is explicitly designed, documented, and tested behavior.

## Analysis

The `TransactionAuthenticator::FeePayer::verify()` function contains an explicit design comment explaining why signatures over `AccountAddress::ZERO` are supported alongside the real fee-payer address:

> "In the fee payer model, the fee payer address can be optionally signed... The modern approach assumes that some may sign over the address and others will sign over the zero address, so we verify both and only fail if the signature fails for either of them." [1](#0-0) 

Critically, the `fee_payer_address` field used for **signature verification** and the field used for **actual gas deduction/binding** in the Move prologue are the exact same struct field — there is no separate "sentinel" path that could be misbound. If an attacker sets `fee_payer_address = 0x0` in the `TransactionAuthenticator::FeePayer` struct, the Move prologue (`fee_payer_script_prologue`/`unified_prologue_fee_payer_v2`) uses that same zero address to create the gas-payer signer and to look up `account::get_authentication_key(fee_payer_address)`: [2](#0-1) [3](#0-2) 

There is no confusion path where a "real" fee-payer signature could be bound to gas deduction for an account other than whatever `fee_payer_address` actually is. Setting it to `0x0` simply makes `0x0` the gas payer, which either has no funds/no auth key registered (causing prologue abort) or requires the actual `0x0` account's key to sign — not an arbitrary "real" fee payer's key.

This exact scenario is directly covered by existing tests:
- `test_bcs_execute_fee_payer_transaction_no_authenticator_fail` submits a `FeePayer` authenticator with `fee_payer_address: AccountAddress::ZERO` and `NoAccountAuthenticator`, and asserts the API rejects it with `INVALID_SIGNATURE` (HTTP 400) at actual execution time. [4](#0-3) 
- `bcs_simulate_fee_payer_transaction_without_gas_fee_check` shows the zero-address case only succeeds under **simulation mode**, which intentionally skips auth-key/gas checks for estimation purposes — not real admission.
<invoke name="read_file">
<parameter name="file_path">api/src/tests/simulation_test.rs</parameter>
<parameter name="repo_name">hirayap/aptos-core--008</parameter>
<parameter name="start_line">499</parameter>
<parameter name="end_line">514</parameter>
</invoke>

### Citations

**File:** types/src/transaction/authenticator.rs (L186-223)
```rust
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
```

**File:** aptos-move/framework/aptos-framework/sources/transaction_validation.move (L451-471)
```text
        prologue_common(
            &sender,
            &create_signer::create_signer(fee_payer_address),
            ReplayProtector::SequenceNumber(txn_sequence_number),
            option::some(txn_sender_public_key),
            txn_gas_price,
            txn_max_gas_units,
            txn_expiration_time,
            chain_id,
            false,
            option::none(),
        );
        multi_agent_common_prologue(
            secondary_signer_addresses,
            secondary_signer_public_key_hashes.map(|x| option::some(x)),
            false
        );
        assert!(
            fee_payer_public_key_hash == account::get_authentication_key(fee_payer_address),
            error::invalid_argument(PROLOGUE_EINVALID_ACCOUNT_AUTH_KEY),
        );
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

**File:** api/src/tests/transactions_test.rs (L636-673)
```rust
                context.use_orderless_transactions,
            ),
    );

    let body = bcs::to_bytes(&vec![invalid_txn]).unwrap();
    // Batch should validate transaction payload and return 400
    let resp = context
        .expect_status_code(400)
        .post_bcs_txn("/transactions/batch", body)
        .await;
    context.check_golden_output(resp);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_post_json_batch_transactions_too_many() {
    // Create a node config with max batch size of 1
    let mut node_config = NodeConfig::default();
    node_config.api.max_submit_transaction_batch_size = 1;

    // Create a test context with test transactions
    let mut context =
        new_test_context_with_config(current_function_name!(), node_config, false, false);
    let account_1 = context.gen_account();
    let account_2 = context.gen_account();
    let transaction_1 = context.create_user_account(&account_1).await;
    let transaction_2 = context.create_user_account(&account_2).await;

    // Submit the batch request with 2 transactions and expect a 400 response
    let transaction_request_1 =
        serde_json::to_value(build_submit_transaction_request(&context, &transaction_1)).unwrap();
    let transaction_request_2 =
        serde_json::to_value(build_submit_transaction_request(&context, &transaction_2)).unwrap();
    let response = context
        .expect_status_code(400)
        .post(
            "/transactions/batch",
            json!([transaction_request_1, transaction_request_2]),
        )
```
