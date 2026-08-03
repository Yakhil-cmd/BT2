## Finding: Confirmed

The claim is valid. `BCSStream` in `bcs_stream.move` is a `struct ... has drop` with only a `has_remaining` query and no automatic "fully consumed" enforcement — callers must explicitly check it themselves. [1](#0-0) 

`sui_derivable_account.move` correctly asserts `!bcs_stream::has_remaining(&mut stream)` after deserializing both the abstract public key and the abstract signature, aborting with `EMALFORMED_DATA` on trailing bytes, and has explicit regression tests for exactly this griefing pattern. [2](#0-1) [3](#0-2) [4](#0-3) 

`ethereum_derivable_account.move`'s `deserialize_abstract_public_key` and `deserialize_abstract_signature` never call `has_remaining`, so trailing bytes are silently ignored. [5](#0-4) 

`solana_derivable_account.move` has the identical gap in both deserializers. [6](#0-5) 

All three modules feed into the same shared dispatch path: `account_abstraction::authenticate` validates that the derived address matches the sender and that the registered function exists, then dispatches into the module-specific `authenticate`/`authenticate_auth_data`, which is where the unchecked `bcs_stream` parsing occurs. [7](#0-6) 

This is reachable directly from an unprivileged transaction: the VM's `AuthenticationProof::Abstract` path in `aptos_vm.rs` dispatches `AbstractAuthenticationData::DerivableV1` (built directly from transaction authenticator bytes) into `dispatchable_authenticate`, which calls `account_abstraction::authenticate`. [8](#0-7) [9](#0-8) 

The `AbstractionAuthData::DerivableV1` variant is exactly `{digest, abstract_signature, abstract_public_key}` — raw bytes attacker-controlled via the transaction authenticator. [10](#0-9) 

### Title
Inconsistent BCS trailing-byte validation across derivable-account abstraction modules allows malleable authenticator encodings for Ethereum/Solana accounts - (File: ethereum_derivable_account.move, solana_derivable_account.move)

### Summary
`sui_derivable_account.move` enforces that the full `abstract_signature` and `abstract_public_key` byte buffers are consumed during BCS parsing (via `assert!(!bcs_stream::has_remaining(...))`), but the same enforcement is missing in `ethereum_derivable_account.move` and `solana_derivable_account.move`. Since `BCSStream` (`bcs_stream.move`) provides no built-in "fully consumed" guarantee — it merely exposes `has_remaining` as an opt-in check — an attacker can append arbitrary trailing bytes to the Ethereum/Solana derivable-account authenticator fields, and both modules will silently ignore them rather than aborting.

### Impact Explanation
This breaks a cross-module invariant that `AbstractionAuthData` consumers should fully consume their signature/public-key input, and creates malleability: the same logical authenticator can now be encoded in multiple distinct byte-level forms (with arbitrary trailing garbage) that all authenticate successfully for Ethereum and Solana derivable accounts, while the identical attack is rejected for Sui accounts. This is an admission-consistency defect — an unprivileged attacker's transaction authenticator bytes are accepted by the VM's authentication dispatch (`account_abstraction::authenticate` → `ethereum_derivable_account::authenticate`/`solana_derivable_account::authenticate`) even though they contain unconsumed/corrupted trailing data, whereas Sui's equivalent path correctly aborts. This does not, however, allow binding to a different sender/signer/fee-payer — the address-consistency assertion in `account_abstraction::authenticate` (`master_signer_addr == derive_account_address(...)`) still holds, and the underlying cryptographic signature check still must pass on the correctly-parsed prefix. The primary impact is therefore transaction/authenticator malleability (multiple valid hashes/encodings for the same authorization) and inconsistent admission semantics across derivable-account types, not sender/signer/fee-payer confusion.

### Likelihood Explanation
High — this is trivially triggerable by any unprivileged party constructing an Ethereum/Solana derivable-account transaction authenticator with appended trailing bytes to the BCS-encoded `abstract_signature` or `abstract_public_key` fields; no privileged access is required.

### Recommendation
Add `assert!(!bcs_stream::has_remaining(&mut stream), EMALFORMED_DATA)` (with an appropriate error code) after parsing in `deserialize_abstract_public_key` and `deserialize_abstract_signature` in both `ethereum_derivable_account.move` and `solana_derivable_account.move`, mirroring the fix already present in `sui_derivable_account.move`.

### Proof of Concept
Construct a valid Solana or Ethereum `SIWSAbstractSignature`/`SIWEAbstractSignature` (or abstract public key) via `bcs::to_bytes`, then append trailing bytes (e.g., `0xDEADBEEF`) before calling `deserialize_abstract_signature`/`deserialize_abstract_public_key` — parsing succeeds without abort, unlike the equivalent `sui_derivable_account::test_deserialize_abstract_signature_with_trailing_bytes` / `test_deserialize_abstract_public_key_with_trailing_bytes` tests which assert `EMALFORMED_DATA`. [4](#0-3)

### Citations

**File:** aptos-move/framework/aptos-stdlib/sources/bcs_stream.move (L24-41)
```text
    struct BCSStream has drop {
        /// Byte buffer containing the serialized data.
        data: vector<u8>,
        /// Cursor indicating the current position in the byte buffer.
        cur: u64,
    }

    /// Constructs a new BCSStream instance from the provided byte array.
    public fun new(data: vector<u8>): BCSStream {
        BCSStream {
            data,
            cur: 0,
        }
    }

    public fun has_remaining(stream: &mut BCSStream): bool {
        stream.cur < stream.data.length()
    }
```

**File:** aptos-move/framework/aptos-framework/sources/account/common_account_abstractions/sui_derivable_account.move (L113-119)
```text
    fun deserialize_abstract_public_key(abstract_public_key: &vector<u8>): SuiAbstractPublicKey {
        let stream = bcs_stream::new(*abstract_public_key);
        let sui_account_address = bcs_stream::deserialize_vector<u8>(&mut stream, |x| deserialize_u8(x));
        let domain = bcs_stream::deserialize_vector<u8>(&mut stream, |x| deserialize_u8(x));
        assert!(!bcs_stream::has_remaining(&mut stream), EMALFORMED_DATA);
        SuiAbstractPublicKey { sui_account_address, domain }
    }
```

**File:** aptos-move/framework/aptos-framework/sources/account/common_account_abstractions/sui_derivable_account.move (L122-132)
```text
    fun deserialize_abstract_signature(abstract_signature: &vector<u8>): SuiAbstractSignature {
        let stream = bcs_stream::new(*abstract_signature);
        let signature_type = bcs_stream::deserialize_u8(&mut stream);
        if (signature_type == 0x00) {
            let signature = bcs_stream::deserialize_vector<u8>(&mut stream, |x| deserialize_u8(x));
            assert!(!bcs_stream::has_remaining(&mut stream), EMALFORMED_DATA);
            SuiAbstractSignature::MessageV1 { signature }
        } else {
            abort(EINVALID_SIGNATURE_TYPE)
        }
    }
```

**File:** aptos-move/framework/aptos-framework/sources/account/common_account_abstractions/sui_derivable_account.move (L409-436)
```text
    #[test]
    #[expected_failure(abort_code = EMALFORMED_DATA)]
    fun test_deserialize_abstract_signature_with_trailing_bytes() {
        let signature_bytes = vector[0, 151, 47, 171, 144, 115, 16, 129, 17, 202, 212, 180, 155, 213, 223, 249, 203, 195, 0, 84, 142, 121, 167, 29, 113, 159, 33, 177, 108, 137, 113, 160, 118, 41, 246, 199, 202, 79, 151, 27, 86, 235, 219, 123, 168, 152, 38, 124, 147, 146, 118, 101, 37, 187, 223, 206, 120, 101, 148, 33, 141, 80, 60, 155, 13, 25, 200, 235, 92, 139, 72, 175, 189, 40, 0, 65, 76, 215, 148, 94, 194, 78, 134, 60, 189, 212, 116, 40, 134, 179, 104, 31, 249, 222, 84, 104, 202];
        let abstract_signature = create_raw_signature(signature_bytes);
        // Append trailing bytes to simulate griefing attack
        abstract_signature.push_back(0xDE);
        abstract_signature.push_back(0xAD);
        abstract_signature.push_back(0xBE);
        abstract_signature.push_back(0xEF);
        // This should fail with EMALFORMED_DATA due to trailing bytes
        deserialize_abstract_signature(&abstract_signature);
    }

    #[test]
    #[expected_failure(abort_code = EMALFORMED_DATA)]
    fun test_deserialize_abstract_public_key_with_trailing_bytes() {
        let sui_account_address = b"0x8d6ce7a3c13617b29aaf7ec58bee5a611606a89c62c5efbea32e06d8d167bd49";
        let domain = b"localhost:3001";
        let abstract_public_key = create_abstract_public_key(sui_account_address, domain);
        // Append trailing bytes to simulate griefing attack
        abstract_public_key.push_back(0xDE);
        abstract_public_key.push_back(0xAD);
        abstract_public_key.push_back(0xBE);
        abstract_public_key.push_back(0xEF);
        // This should fail with EMALFORMED_DATA due to trailing bytes
        deserialize_abstract_public_key(&abstract_public_key);
    }
```

**File:** aptos-move/framework/aptos-framework/sources/account/common_account_abstractions/ethereum_derivable_account.move (L75-99)
```text
    fun deserialize_abstract_public_key(abstract_public_key: &vector<u8>): SIWEAbstractPublicKey {
        let stream = bcs_stream::new(*abstract_public_key);
        let ethereum_address = bcs_stream::deserialize_vector<u8>(&mut stream, |x| deserialize_u8(x));
        let domain = bcs_stream::deserialize_vector<u8>(&mut stream, |x| deserialize_u8(x));
        SIWEAbstractPublicKey { ethereum_address, domain }
    }

    /// Returns a tuple of the signature type and the signature.
    /// We include the issued_at in the signature as it is a required field in the SIWE standard.
    fun deserialize_abstract_signature(abstract_signature: &vector<u8>): SIWEAbstractSignature {
        let stream = bcs_stream::new(*abstract_signature);
        let signature_type = bcs_stream::deserialize_u8(&mut stream);
        if (signature_type == 0x00) {
            let issued_at = bcs_stream::deserialize_vector<u8>(&mut stream, |x| deserialize_u8(x));
            let signature = bcs_stream::deserialize_vector<u8>(&mut stream, |x| deserialize_u8(x));
            SIWEAbstractSignature::MessageV1 { issued_at: string::utf8(issued_at), signature }
        } else if (signature_type == 0x01) {
            let scheme = bcs_stream::deserialize_vector<u8>(&mut stream, |x| deserialize_u8(x));
            let issued_at = bcs_stream::deserialize_vector<u8>(&mut stream, |x| deserialize_u8(x));
            let signature = bcs_stream::deserialize_vector<u8>(&mut stream, |x| deserialize_u8(x));
            SIWEAbstractSignature::MessageV2 { scheme: string::utf8(scheme), issued_at: string::utf8(issued_at), signature }
        } else {
            abort(EINVALID_SIGNATURE_TYPE)
        }
    }
```

**File:** aptos-move/framework/aptos-framework/sources/account/common_account_abstractions/solana_derivable_account.move (L60-78)
```text
    fun deserialize_abstract_public_key(abstract_public_key: &vector<u8>):
    (vector<u8>, vector<u8>) {
        let stream = bcs_stream::new(*abstract_public_key);
        let base58_public_key = bcs_stream::deserialize_vector<u8>(&mut stream, |x| deserialize_u8(x));
        let domain = bcs_stream::deserialize_vector<u8>(&mut stream, |x| deserialize_u8(x));
        (base58_public_key, domain)
    }

    /// Returns a tuple of the signature type and the signature.
    fun deserialize_abstract_signature(abstract_signature: &vector<u8>): SIWSAbstractSignature {
        let stream = bcs_stream::new(*abstract_signature);
        let signature_type = bcs_stream::deserialize_u8(&mut stream);
        if (signature_type == 0x00) {
            let signature = bcs_stream::deserialize_vector<u8>(&mut stream, |x| deserialize_u8(x));
            SIWSAbstractSignature::MessageV1 { signature }
        } else {
            abort(EINVALID_SIGNATURE_TYPE)
        }
    }
```

**File:** aptos-move/framework/aptos-framework/sources/account/account_abstraction.move (L269-301)
```text
    fun authenticate(
        account: signer,
        func_info: FunctionInfo,
        signing_data: AbstractionAuthData,
    ): signer acquires DispatchableAuthenticator, DerivableDispatchableAuthenticator {
        let master_signer_addr = signer::address_of(&account);

        if (signing_data.is_derivable()) {
            assert!(features::is_derivable_account_abstraction_enabled(), error::invalid_state(EDERIVABLE_ACCOUNT_ABSTRACTION_NOT_ENABLED));
            assert!(master_signer_addr == derive_account_address(func_info, signing_data.derivable_abstract_public_key()), error::invalid_state(EINCONSISTENT_SIGNER_ADDRESS));

            let func_infos = dispatchable_derivable_authenticator_internal();
            assert!(func_infos.contains(&func_info), error::not_found(EFUNCTION_INFO_EXISTENCE));
        } else {
            assert!(features::is_account_abstraction_enabled(), error::invalid_state(EACCOUNT_ABSTRACTION_NOT_ENABLED));

            let func_infos = dispatchable_authenticator_internal(master_signer_addr);
            assert!(func_infos.contains(&func_info), error::not_found(EFUNCTION_INFO_EXISTENCE));
        };

        let returned_signer = if (features::is_function_value_dispatch_enabled()) {
            dispatch_authenticate_hook(account, signing_data, &func_info)
        } else {
            function_info::load_module_from_function(&func_info);
            dispatchable_authenticate(account, signing_data, &func_info)
        };
        // Returned signer MUST represent the same account address. Otherwise, it may break the invariant of Aptos blockchain!
        assert!(
            master_signer_addr == signer::address_of(&returned_signer),
            error::invalid_state(EINCONSISTENT_SIGNER_ADDRESS)
        );
        returned_signer
    }
```

**File:** aptos-move/aptos-vm/src/aptos_vm.rs (L2018-2052)
```rust
        let sender_signers = itertools::zip_eq(senders, proofs)
            .map(|(sender, proof)| match proof {
                AuthenticationProof::Abstract {
                    function_info,
                    auth_data,
                } => {
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
                            sender,
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
                        Err(VMStatus::error(StatusCode::FEATURE_UNDER_GATING, None))
                    }
                },
```

**File:** aptos-move/aptos-vm/src/aptos_vm.rs (L3702-3726)
```rust
fn dispatchable_authenticate(
    session: &mut SessionExt<impl AptosMoveResolver>,
    gas_meter: &mut impl GasMeter,
    account: AccountAddress,
    function_info: FunctionInfo,
    auth_data: &AbstractAuthenticationData,
    traversal_context: &mut TraversalContext,
    module_storage: &impl ModuleStorage,
) -> VMResult<Vec<u8>> {
    let auth_data = bcs::to_bytes(auth_data).expect("from rust succeeds");
    let mut params = serialize_values(&vec![
        MoveValue::Signer(account),
        function_info.as_move_value(),
    ]);
    params.push(auth_data);
    session
        .execute_function_bypass_visibility(
            &ACCOUNT_ABSTRACTION_MODULE,
            AUTHENTICATE,
            vec![],
            params,
            gas_meter,
            traversal_context,
            module_storage,
        )
```

**File:** aptos-move/framework/aptos-framework/sources/account/auth_data.move (L7-17)
```text
    enum AbstractionAuthData has copy, drop {
        V1 {
            digest: vector<u8>,
            authenticator: vector<u8>
        },
        DerivableV1 {
            digest: vector<u8>,
            abstract_signature: vector<u8>,
            abstract_public_key: vector<u8>,
        },
    }
```
