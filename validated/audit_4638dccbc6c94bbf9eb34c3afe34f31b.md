Based on my investigation, I found a concrete admission-boundary gap in the new encrypted-transaction feature: the cryptographic binding between the ciphertext and the sender/signer set (`EncryptedPayload::verify` / `PayloadAssociatedData`) is only invoked from the REST API's `validate_signed_transaction_payload` path in `api/src/transactions.rs`, and I could not find any call to this check in `vm-validator`, `AptosVM::validate_transaction` (the `VMValidator` impl), the mempool insertion path, or the Move prologue (`transaction_validation.move`). This means the sender/signer binding of the ciphertext is enforced only at one ingress point (the local node's REST submission handler) rather than at the actual VM/mempool admission boundary that all transactions must pass through.

### Title
Encrypted transaction sender/signer binding (`PayloadAssociatedData`) is enforced only in the REST submission handler, not in VM/mempool admission - (File: `api/src/transactions.rs`, `aptos-move/aptos-vm/src/aptos_vm.rs`)

### Summary
Encrypted transactions carry a ciphertext whose AEAD associated data commits to `(sender, signer_auth_keys)` via `EncryptedPayload::verify` / `PayloadAssociatedData` [1](#0-0) . This binding check is only ever called from `TransactionsApi::validate_signed_transaction_payload` in the REST BCS/JSON submission handler [2](#0-1) . The Ed25519/authenticator signature only covers the ciphertext blob (via `as_encrypted_variant`), not the association between ciphertext and sender [3](#0-2) .

### Finding Description
The signature verification path (`TransactionAuthenticator::verify`, used everywhere: mempool `check_signature`/`verify_signature`, `AptosVM::validate_transaction`, and execution) only authenticates the raw transaction fields (sender, sequence number, gas, expiration, chain id, and the *ciphertext bytes themselves*) [4](#0-3) . It never authenticates that the ciphertext was actually encrypted *for* this sender/signer set — that binding is a separate cryptographic check (`payload.verify(sender, signer_auth_keys)` against `PayloadAssociatedData`) that lives entirely outside the signature.

The only place this separate binding check is performed is in the API layer's `validate_signed_transaction_payload`, which runs when a client submits a BCS/JSON transaction directly to a node's REST `/transactions` endpoint [5](#0-4) . I traced the two other transaction admission paths that a signed transaction can enter through:
- `AptosVM::validate_transaction` (the `VMValidator` trait impl used by `vm-validator` when mempool asks the VM to (re)validate a transaction, and used when a transaction arrives from a peer's mempool broadcast) — this only checks authenticator feature-gating, encrypted-feature-flag gating, and `check_signature()`, with no call to `EncryptedPayload::verify`/`all_signer_auth_keys` [6](#0-5) .
- The Move prologue (`prologue_common`/`multi_agent_common_prologue`/`versioned_prologue` in `transaction_validation.move`), which is the actual on-chain admission gate re-run before every execution, checks expiration, chain id, auth key, replay protection, and gas balance — it has no notion of the encrypted-payload associated-data binding at all [7](#0-6) .

Consequently, a transaction that bypasses the specific REST BCS/JSON handler code path in `api/src/transactions.rs` (e.g., transactions relayed peer-to-peer through the mempool network protocol between validators/full nodes, or submitted through any future/alternate ingress that constructs a `SignedTransaction` and hands it to `vm-validator`/`AptosVM` directly) will pass full mempool and VM admission and be queued for decryption/execution even though its ciphertext's associated data does not match its claimed sender/signer set.

### Impact Explanation
If the associated-data binding is skipped, an attacker can take a validly signed, arbitrary encrypted ciphertext (e.g., replaying or forwarding someone else's already-published encrypted ciphertext, or crafting a ciphertext associated with a different sender/signer set) and get it admitted into mempool and delivered into the decryption pipeline under a sender/signature of their own choosing, since only the raw-transaction fields (sender, sequence number, gas, expiration, chain-id) are Ed25519-signed and the associated-data binding that ties the ciphertext to that specific sender is never re-checked outside the one REST handler. This is exactly the class of "authenticator/approval validation accepting the wrong signing material or wrong approval set" and "pre-validation mismatch that causes a transaction which should fail admission to execute" described in the Admission Impact Gate. Because encrypted transactions are decrypted by a committee and then executed with the sender's authority (`self.sender`) via `execute_script_or_entry_function`, a missing binding check could let an attacker submit a transaction with a mismatched ciphertext/sender pairing that still reaches execution under the wrong sender context.

### Likelihood Explanation
This is contingent on the `ENCRYPTED_TRANSACTIONS` feature flag being enabled (currently used in forge/e2e tests, not default-enabled in mainnet) [8](#0-7) , and requires the ciphertext to already have been produced (i.e., valid ciphertext bytes, since raw garbage would fail decryption later and only cost the surcharge). I was **not able to fully confirm** whether `all_signer_auth_keys`/`payload.verify` is invoked somewhere else I didn't find (e.g., inside the decryption pipeline builder's `do_final_decryption`/`try_into_decrypted` path in consensus, which I inspected and found only checks `payload_hash` and `claimed_entry_fun`, not sender/signer binding) [9](#0-8) . Given the exhaustive grep across the repo showed `PayloadAssociatedData`/`all_signer_auth_keys` used only in `api/src/transactions.rs`, `api/types/src/transaction.rs` (type definitions), and test files, likelihood that this check is genuinely missing from the VM/mempool/decryption admission paths is moderate-to-high, but this is a fairly new, not-yet-fully-shipped feature and I could not verify runtime behavior with a live decryption pipeline to be fully certain no other layer re-derives and checks this binding.

### Recommendation
Move the `EncryptedPayload::verify(sender, signer_auth_keys)` associated-data check out of the REST-only `validate_signed_transaction_payload` and into a path that all admission routes share — ideally as part of `AptosVM::validate_transaction` (`VMValidator` impl) and/or the Move prologue for encrypted transactions, so that mempool-relayed and any other-sourced transactions are held to the same binding guarantee as directly-submitted REST transactions before being accepted into mempool or forwarded into the decryption pipeline.

### Proof of Concept
1. Enable `FeatureFlag::ENCRYPTED_TRANSACTIONS` on a test network.
2. Construct `EncryptedInner` with a ciphertext whose associated data was generated for `sender_A`/`signer_keys_A`.
3. Build a `SignedTransaction` with `sender = sender_B` (a different account) and a valid Ed25519 signature from `sender_B`'s key over `as_encrypted_variant()` (i.e., over the ciphertext bytes, which is sender-independent).
4. Submit this transaction directly to `vm-validator`/mempool via the internal network broadcast protocol (bypassing `api/src/transactions.rs::validate_signed_transaction_payload`), or via any test harness that calls `AptosVM::validate_transaction` directly rather than through the REST endpoint.
5. Observe that `check_authenticator_features`, `check_signature`, and the prologue all succeed despite the ciphertext/sender mismatch, since none of them call `EncryptedPayload::verify`, confirming the binding is not enforced at the VM/mempool admission boundary [10](#0-9) .

### Citations

**File:** types/src/transaction/encrypted_payload.rs (L255-262)
```rust
    pub fn verify(
        &self,
        sender: AccountAddress,
        signer_auth_keys: Vec<(AccountAddress, AuthenticationKey)>,
    ) -> anyhow::Result<()> {
        let associated_data = PayloadAssociatedData::new(sender, signer_auth_keys);
        self.ciphertext().verify(&associated_data)
    }
```

**File:** types/src/transaction/encrypted_payload.rs (L286-333)
```rust
    #[test]
    fn try_into_decrypted_accepts_matching_hash() {
        let plaintext = DecryptedPlaintext::new(TransactionExecutable::Empty, [7; 16]);
        let mut encrypted = encrypted_with_hash(CryptoHash::hash(&plaintext), None);

        encrypted
            .try_into_decrypted(EvalProof::random(), plaintext)
            .unwrap();
        assert!(matches!(encrypted, EncryptedPayload::Decrypted { .. }));
    }

    #[test]
    fn try_into_decrypted_rejects_mismatched_hash() {
        let plaintext = DecryptedPlaintext::new(TransactionExecutable::Empty, [7; 16]);
        let mut encrypted = encrypted_with_hash(HashValue::random(), None);

        assert_eq!(
            encrypted.try_into_decrypted(EvalProof::random(), plaintext),
            Err(DecryptionFailureReason::PayloadHashMismatch)
        );
        assert!(matches!(encrypted, EncryptedPayload::Encrypted(_)));
    }

    #[test]
    fn try_into_decrypted_rejects_mismatched_entry_fun() {
        use crate::transaction::EntryFunction;
        use move_core_types::ident_str;

        let entry_fun = EntryFunction::new(
            ModuleId::new(AccountAddress::ONE, ident_str!("coin").to_owned()),
            ident_str!("transfer").to_owned(),
            vec![],
            vec![],
        );
        let plaintext =
            DecryptedPlaintext::new(TransactionExecutable::EntryFunction(entry_fun), [7; 16]);
        let claim = ClaimedEntryFunction {
            module: ModuleId::new(AccountAddress::ONE, ident_str!("other_module").to_owned()),
            function: None,
        };
        let mut encrypted = encrypted_with_hash(CryptoHash::hash(&plaintext), Some(claim));

        assert_eq!(
            encrypted.try_into_decrypted(EvalProof::random(), plaintext),
            Err(DecryptionFailureReason::ClaimedEntryFunctionMismatch)
        );
        assert!(matches!(encrypted, EncryptedPayload::Encrypted(_)));
    }
```

**File:** api/src/transactions.rs (L1237-1278)
```rust
    fn get_signed_transaction(
        &self,
        ledger_info: &LedgerInfo,
        data: SubmitTransactionPost,
    ) -> Result<SignedTransaction, SubmitTransactionError> {
        match data {
            SubmitTransactionPost::Bcs(data) => {
                let signed_transaction: SignedTransaction =
                    bcs::from_bytes_with_limit(&data.0, Self::MAX_SIGNED_TRANSACTION_DEPTH)
                        .context("Failed to deserialize input into SignedTransaction")
                        .map_err(|err| {
                            SubmitTransactionError::bad_request_with_code(
                                err,
                                AptosErrorCode::InvalidInput,
                                ledger_info,
                            )
                        })?;
                // Verify the signed transaction
                self.validate_signed_transaction_payload(ledger_info, &signed_transaction)?;
                // TODO: Verify script args?

                Ok(signed_transaction)
            },
            SubmitTransactionPost::Json(data) => self
                .context
                .latest_state_view_poem(ledger_info)?
                .as_converter(self.context.db.clone(), self.context.indexer_reader.clone())
                .try_into_signed_transaction_poem(data.0, self.context.chain_id())
                .context("Failed to create SignedTransaction from SubmitTransactionRequest")
                .map_err(|err| {
                    SubmitTransactionError::bad_request_with_code(
                        err,
                        AptosErrorCode::InvalidInput,
                        ledger_info,
                    )
                })
                .and_then(|signed_transaction| {
                    self.validate_signed_transaction_payload(ledger_info, &signed_transaction)?;
                    Ok(signed_transaction)
                }),
        }
    }
```

**File:** api/src/transactions.rs (L1376-1393)
```rust
                let signer_auth_keys = signed_transaction
                    .authenticator()
                    .all_signer_auth_keys(signed_transaction.sender())
                    .ok_or_else(|| {
                        SubmitTransactionError::bad_request_with_code(
                            "Encrypted transactions are not supported with this authenticator type",
                            AptosErrorCode::InvalidInput,
                            ledger_info,
                        )
                    })?;

                if let Err(e) = payload.verify(signed_transaction.sender(), signer_auth_keys) {
                    return Err(SubmitTransactionError::bad_request_with_code(
                        e.context("Encrypted transaction payload could not be verified"),
                        AptosErrorCode::InvalidInput,
                        ledger_info,
                    ));
                }
```

**File:** types/src/transaction/mod.rs (L690-714)
```rust
    /// Converts a RawTransaction with an EncryptedPayload into a variant that uses
    /// TransactionExecutable::Encrypted for signature verification.
    /// This is needed because signatures are verified over the executable, not the encrypted ciphertext.
    pub fn as_encrypted_variant(&self) -> Cow<'_, Self> {
        match &self.payload {
            TransactionPayload::EncryptedPayload(EncryptedPayload::Decrypted {
                original, ..
            })
            | TransactionPayload::EncryptedPayload(EncryptedPayload::FailedDecryption {
                original,
                ..
            }) => Cow::Owned(RawTransaction {
                sender: self.sender,
                sequence_number: self.sequence_number,
                payload: TransactionPayload::EncryptedPayload(EncryptedPayload::Encrypted(
                    original.clone(),
                )),
                max_gas_amount: self.max_gas_amount,
                gas_unit_price: self.gas_unit_price,
                expiration_timestamp_secs: self.expiration_timestamp_secs,
                chain_id: self.chain_id,
            }),
            _ => Cow::Borrowed(self),
        }
    }
```

**File:** types/src/transaction/authenticator.rs (L159-178)
```rust
    /// Return Ok if all AccountAuthenticator's public keys match their signatures, Err otherwise
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
```

**File:** aptos-move/aptos-vm/src/aptos_vm.rs (L3478-3526)
```rust
impl VMValidator for AptosVM {
    /// Determine if a transaction is valid. Will return `None` if the transaction is accepted,
    /// `Some(Err)` if the VM rejects it, with `Err` as an error code. Verification performs the
    /// following steps:
    /// 1. The signature on the `SignedTransaction` matches the public key included in the
    ///    transaction
    /// 2. The script to be executed is under given specific configuration.
    /// 3. Invokes `Account.prologue`, which checks properties such as the transaction has the
    /// right sequence number and the sender has enough balance to pay for the gas.
    /// TBD:
    /// 1. Transaction arguments matches the main function's type signature.
    ///    We don't check this item for now and would execute the check at execution time.
    fn validate_transaction(
        &self,
        transaction: SignedTransaction,
        state_view: &impl StateView,
        module_storage: &impl ModuleStorage,
    ) -> VMValidatorResult {
        let _timer = TXN_VALIDATION_SECONDS.start_timer();
        let log_context = AdapterLogSchema::new(state_view.id(), 0);

        if let Err(err) = self.check_authenticator_features(transaction.authenticator_ref()) {
            return VMValidatorResult::error(err.status_code());
        }

        if !self
            .features()
            .is_enabled(FeatureFlag::ALLOW_SERIALIZED_SCRIPT_ARGS)
        {
            if let Ok(TransactionExecutableRef::Script(script)) =
                transaction.payload().executable_ref()
            {
                for arg in script.args() {
                    if let TransactionArgument::Serialized(_) = arg {
                        return VMValidatorResult::error(StatusCode::FEATURE_UNDER_GATING);
                    }
                }
            }
        }

        if transaction.payload().is_encrypted_variant()
            && !self.features().is_encrypted_transactions_enabled()
        {
            return VMValidatorResult::error(StatusCode::FEATURE_UNDER_GATING);
        }

        let Ok(txn) = transaction.check_signature() else {
            return VMValidatorResult::error(StatusCode::INVALID_SIGNATURE);
        };
```

**File:** aptos-move/framework/aptos-framework/sources/transaction_validation.move (L120-205)
```text
    fun prologue_common(
        sender: &signer,
        gas_payer: &signer,
        replay_protector: ReplayProtector,
        txn_authentication_key: Option<vector<u8>>,
        txn_gas_price: u64,
        txn_max_gas_units: u64,
        txn_expiration_time: u64,
        chain_id: u8,
        is_simulation: bool,
        txn_limits_request: Option<UserTxnLimitsRequest>,
    ) {
        let sender_address = signer::address_of(sender);
        let gas_payer_address = signer::address_of(gas_payer);
        assert!(
            timestamp::now_seconds() < txn_expiration_time,
            error::invalid_argument(PROLOGUE_ETRANSACTION_EXPIRED),
        );
        assert!(chain_id::get() == chain_id, error::invalid_argument(PROLOGUE_EBAD_CHAIN_ID));

        // TODO[Orderless]: Here, we are maintaining the same order of validation steps as before orderless txns were introduced.
        // Ideally, do the replay protection check in the end after the authentication key check and gas payment checks.

        // Check if the authentication key is valid
        if (!skip_auth_key_check(is_simulation, &txn_authentication_key)) {
            if (txn_authentication_key.is_some()) {
                let authentication_key = if (
                    sender_address != gas_payer_address &&
                        !account::exists_at(sender_address) &&
                        features::sponsored_automatic_account_creation_enabled()
                ) {
                    // This is a sponsored transaction with account that does
                    // not exist and there is no default account resource.
                    bcs::to_bytes(&sender_address)
                } else {
                    account::get_authentication_key(sender_address)
                };
                assert!(
                    txn_authentication_key.destroy_some() == authentication_key,
                    error::invalid_argument(PROLOGUE_EINVALID_ACCOUNT_AUTH_KEY),
                );
            } else {
                assert!(
                    allow_missing_txn_authentication_key(sender_address),
                    error::invalid_argument(PROLOGUE_EINVALID_ACCOUNT_AUTH_KEY)
                );
            };
        };

        // Check for replay protection
        match (replay_protector) {
            SequenceNumber(txn_sequence_number) => {
                check_for_replay_protection_regular_txn(
                    sender_address,
                    gas_payer_address,
                    txn_sequence_number,
                );
            },
            Nonce(nonce) => {
                check_for_replay_protection_orderless_txn(
                    sender_address,
                    nonce,
                    txn_expiration_time,
                );
            }
        };

        if (txn_limits_request.is_some()) {
            transaction_limits::validate_high_txn_limits(
                gas_payer_address,
                txn_limits_request.destroy_some(),
            );
        };

        // Check if the gas payer has enough balance to pay for the transaction
        let max_transaction_fee = txn_gas_price * txn_max_gas_units;
        if (!skip_gas_payment(
            is_simulation,
            gas_payer_address
        )) {
            assert!(
                aptos_account::is_fungible_balance_at_least(gas_payer_address, max_transaction_fee),
                error::invalid_argument(PROLOGUE_ECANT_PAY_GAS_DEPOSIT)
            );
        };
    }
```

**File:** testsuite/forge-cli/src/suites/realistic_environment.rs (L564-567)
```rust
            let mut features = Features::default();
            features.enable(FeatureFlag::ENCRYPTED_TRANSACTIONS);
            helm_values["chain"]["initial_features_override"] =
                serde_yaml::to_value(features).expect("must serialize");
```
