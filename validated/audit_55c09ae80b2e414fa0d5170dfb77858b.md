## Verdict: No vulnerability found for this question.

### Analysis

The proposed exploit assumes `fee_payer_address` (used to build the Move signer in the prologue via `create_signer::create_signer(fee_payer_address)`) can diverge from the address whose key actually signed the fee-payer authenticator. Tracing the data flow shows this is not possible through the normal admission path:

1. **Fee payer address is a single source of truth.** `TransactionMetadata::new` sets `fee_payer: txn.authenticator_ref().fee_payer_address()`, pulling the address directly out of the `TransactionAuthenticator::FeePayer { fee_payer_address, fee_payer_signer, .. }` enum variant. [1](#0-0) 

2. **`SerializedSigners::fee_payer()` is derived from the same `fee_payer_address`**, not an independently-parsed value — the VM builds `serialized_signers` from `txn_data.fee_payer()`/the same authenticator address before invoking prologue, so `native_create_signer` and the `fee_payer_address` argument passed to `fee_payer_script_prologue`/`unified_prologue_fee_payer*` always reference the identical address. [2](#0-1) [3](#0-2) [4](#0-3) 

3. **The prologue independently binds the claimed `fee_payer_address` to a real on-chain authentication key.** Both `fee_payer_script_prologue`/`fee_payer_script_prologue_extended` and the newer `unified_prologue_fee_payer_v2` explicitly assert that `fee_payer_public_key_hash == account::get_authentication_key(fee_payer_address)` (or, in the AA case, that account_abstraction dispatch is enabled for that address). [5](#0-4) [6](#0-5) 

4. **The `fee_payer_public_key_hash`/auth proof used in that check is derived from `fee_payer_signer` (the actual authenticator that signed the transaction), not from unprivileged/attacker-controlled sender input independent of the signature.** `fee_payer_authentication_proof` in `TransactionMetadata` comes from `txn.authenticator().fee_payer_signer().authentication_proof()`, i.e., the cryptographic object the attacker cannot forge without the fee payer's private key. [7](#0-6) 

5. **Signature verification (`TransactionAuthenticator::verify`) checks that every `AccountAuthenticator` (including the fee-payer authenticator) has a signature valid against the "raw transaction with data" hash**, which itself commits to `fee_payer_address` in the signed message (`RawTransactionWithData::new_fee_payer(raw_txn, secondary_signers, fee_payer_address)`), so a signature over one `fee_payer_address` will not verify if the transaction claims a different `fee_payer_address` in the authenticator. This is corroborated by `sign_aa_transaction`, which builds the signed pre-image including `fee_payer_address` before generating the fee-payer authenticator's signature. [8](#0-7) 

An unprivileged sender can *construct* a raw `TransactionAuthenticator::FeePayer` struct with a mismatched `fee_payer_address` field and an authenticator signed for a different address (as done deliberately in a unit test to probe this exact scenario), but signature verification during admission would reject it because the signed pre-image binds the address into the hash that is verified. [9](#0-8) 

### Why this is not exploitable
- `fee_payer_address` and the value fed to `create_signer::create_signer` and `serialized_signers.fee_payer()` are the *same* value read once from the authenticator by `TransactionMetadata::new` — there is no independent second parse that could diverge.
- The prologue re-derives/validates that address against the on-chain authentication key using the authenticator's own proof (`fee_payer_authentication_proof`), which is bound cryptographically to `fee_payer_address` through the signed pre-image (`RawTransactionWithData::new_fee_payer`).
- A crafted mismatch (attacker claims `fee_payer_address = X` but signs with a key belonging to `Y`) would fail transaction-level signature verification before reaching the prologue at all, and separately would fail the `account::get_authentication_key(fee_payer_address) == fee_payer_public_key_hash` prologue assertion if it somehow bypassed verification.

I could not fully trace the exact byte-level content of `TransactionAuthenticator::verify` (lines 161–281 were blank/truncated in the index) or `RawTransactionWithData`'s exact BCS layout confirming `fee_payer_address` is included in the signed hash for every code path (e.g., AA/keyless fee-payer variants). This is a limitation of the index rather than evidence of a bug — if you need full certainty on this cryptographic binding across all authenticator types, a Devin session with full file access would be needed to review `types/src/transaction/authenticator.rs` lines 161–281 and `RawTransactionWithData`'s `Serialize` implementation in full.

#### No vulnerability found for this question.

### Citations

**File:** aptos-move/aptos-vm/src/transaction_metadata.rs (L142-146)
```rust
            fee_payer: txn.authenticator_ref().fee_payer_address(),
            fee_payer_authentication_proof: txn
                .authenticator()
                .fee_payer_signer()
                .map(|signer| signer.authentication_proof()),
```

**File:** aptos-move/aptos-vm/src/aptos_vm.rs (L229-250)
```rust
pub(crate) struct SerializedSigners {
    senders: Vec<Vec<u8>>,
    fee_payer: Option<Vec<u8>>,
}

impl SerializedSigners {
    pub fn new(senders: Vec<Vec<u8>>, fee_payer: Option<Vec<u8>>) -> Self {
        Self { senders, fee_payer }
    }

    pub fn sender(&self) -> Vec<u8> {
        self.senders[0].clone()
    }

    pub fn senders(&self) -> Vec<Vec<u8>> {
        self.senders.clone()
    }

    pub fn fee_payer(&self) -> Option<Vec<u8>> {
        self.fee_payer.clone()
    }
}
```

**File:** aptos-move/aptos-vm/src/transaction_validation.rs (L170-216)
```rust
        let (prologue_function_name, serialized_args) = if let (true, Some(fee_payer_auth_key)) = (
            txn_data.fee_payer().is_some(),
            txn_data
                .fee_payer_authentication_proof
                .as_ref()
                .map(|proof| proof.optional_auth_key()),
        ) {
            let serialized_args = vec![
                serialized_signers.sender(),
                serialized_signers
                    .fee_payer()
                    .ok_or_else(|| VMStatus::error(StatusCode::UNREACHABLE, None))?,
                txn_authentication_key
                    .as_move_value()
                    .simple_serialize()
                    .unwrap(),
                fee_payer_auth_key
                    .as_move_value()
                    .simple_serialize()
                    .unwrap(),
                replay_protector_move_value,
                MoveValue::vector_address(txn_data.secondary_signers())
                    .simple_serialize()
                    .unwrap(),
                MoveValue::Vector(secondary_auth_keys)
                    .simple_serialize()
                    .unwrap(),
                MoveValue::U64(txn_gas_price.into())
                    .simple_serialize()
                    .unwrap(),
                MoveValue::U64(txn_max_gas_units.into())
                    .simple_serialize()
                    .unwrap(),
                MoveValue::U64(txn_expiration_timestamp_secs)
                    .simple_serialize()
                    .unwrap(),
                MoveValue::U8(chain_id.id()).simple_serialize().unwrap(),
                MoveValue::Bool(is_simulation).simple_serialize().unwrap(),
            ];
            (
                if features.is_transaction_payload_v2_enabled() {
                    &APTOS_TRANSACTION_VALIDATION.unified_prologue_fee_payer_v2_name
                } else {
                    &APTOS_TRANSACTION_VALIDATION.unified_prologue_fee_payer_name
                },
                serialized_args,
            )
```

**File:** aptos-move/framework/natives/src/create_signer.rs (L20-32)
```rust
pub(crate) fn native_create_signer(
    context: &mut SafeNativeContext,
    ty_args: &[Type],
    mut arguments: VecDeque<Value>,
) -> SafeNativeResult<SmallVec<[Value; 1]>> {
    debug_assert!(ty_args.is_empty());
    debug_assert!(arguments.len() == 1);

    context.charge(ACCOUNT_CREATE_SIGNER_BASE)?;

    let address = safely_pop_arg!(arguments, AccountAddress);
    Ok(smallvec![Value::master_signer(address)])
}
```

**File:** aptos-move/framework/aptos-framework/sources/transaction_validation.move (L436-472)
```text
    fun fee_payer_script_prologue(
        sender: signer,
        txn_sequence_number: u64,
        txn_sender_public_key: vector<u8>,
        secondary_signer_addresses: vector<address>,
        secondary_signer_public_key_hashes: vector<vector<u8>>,
        fee_payer_address: address,
        fee_payer_public_key_hash: vector<u8>,
        txn_gas_price: u64,
        txn_max_gas_units: u64,
        txn_expiration_time: u64,
        chain_id: u8,
    ) {
        // prologue_common and multi_agent_common_prologue with is_simulation set to false behaves identically to the
        // original fee_payer_script_prologue function.
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
    }
```

**File:** aptos-move/framework/aptos-framework/sources/transaction_validation.move (L751-792)
```text
    fun unified_prologue_fee_payer_v2(
        sender: signer,
        fee_payer: signer,
        txn_sender_public_key: Option<vector<u8>>,
        fee_payer_public_key_hash: Option<vector<u8>>,
        replay_protector: ReplayProtector,
        secondary_signer_addresses: vector<address>,
        secondary_signer_public_key_hashes: vector<Option<vector<u8>>>,
        txn_gas_price: u64,
        txn_max_gas_units: u64,
        txn_expiration_time: u64,
        chain_id: u8,
        is_simulation: bool,
    ) {
        prologue_common(
            &sender,
            &fee_payer,
            replay_protector,
            txn_sender_public_key,
            txn_gas_price,
            txn_max_gas_units,
            txn_expiration_time,
            chain_id,
            is_simulation,
            option::none(),
        );
        multi_agent_common_prologue(secondary_signer_addresses, secondary_signer_public_key_hashes, is_simulation);
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
    }
```

**File:** types/src/transaction/mod.rs (L581-597)
```rust
        if let Some((fee_payer_address, fee_payer_auth)) = fee_payer {
            let user_signed_message = RawTransactionWithData::new_fee_payer(
                self.clone(),
                secondary_signers.clone(),
                fee_payer_address,
            );
            let fee_payer_authenticator = gen_auth(fee_payer_auth, &user_signed_message)?;
            Ok(SignatureCheckedTransaction(
                SignedTransaction::new_fee_payer(
                    self,
                    sender_authenticator,
                    secondary_signers,
                    secondary_authenticators,
                    fee_payer_address,
                    fee_payer_authenticator,
                ),
            ))
```

**File:** api/src/tests/transactions_test.rs (L907-965)
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

    let another_txn = match another_txn.authenticator() {
        TransactionAuthenticator::FeePayer {
            sender: _,
            secondary_signer_addresses: _,
            secondary_signers: _,
            fee_payer_address,
            fee_payer_signer,
        } => {
            let auth = TransactionAuthenticator::fee_payer(
                sender,
                secondary_signer_addresses,
                secondary_signers,
                fee_payer_address,
                fee_payer_signer,
            );
            SignedTransaction::new_signed_transaction(another_raw_txn, auth)
        },
        _ => panic!(
            "expecting TransactionAuthenticator::FeePayer, but got: {:?}",
            txn.authenticator()
        ),
    };
```
