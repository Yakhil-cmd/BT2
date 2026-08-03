The evidence confirms the vulnerability. The `ClientDataType` enum (`Get`/`Create`) is only referenced in a test file (`api/src/tests/webauthn_secp256r1_ecdsa.rs`) — it is never checked anywhere in production code. The actual verification logic in `PartialAuthenticatorAssertionResponse::verify` and `verify_arbitrary_msg` never inspects `collected_client_data.ty` at all.

### Title
WebAuthn ceremony-type (`CollectedClientData.ty`) is never validated in `PartialAuthenticatorAssertionResponse::verify`, allowing `Create`-type (or any other type) client data to authenticate transactions - (File: `types/src/transaction/webauthn.rs`)

### Summary
`PartialAuthenticatorAssertionResponse::verify` (used by `AnySignature::WebAuthn` during `SignedTransaction::verify_signature`/`check_signature`, which mempool and the VM validator invoke on transaction admission) deserializes `client_data_json` into a `CollectedClientData` struct, but only validates the `challenge` field and the cryptographic signature. It never asserts that `collected_client_data.ty == ClientDataType::Get`.

### Finding Description
The verification routine is: [1](#0-0) 

It:
1. Parses `client_data_json` into `CollectedClientData` (which includes `ty`, `challenge`, `origin`, `cross_origin`).
2. Extracts `challenge` and checks it against the expected SHA3-256 digest of the raw transaction's signing message via `verify_expected_challenge_from_message_matches_actual`.
3. Builds `verification_data` = `authenticator_data || SHA256(client_data_json)` and verifies the secp256r1 signature over it.

At no point is `collected_client_data.ty` compared against the expected ceremony type (`ClientDataType::Get`, i.e., `webauthn.get`). The `ClientDataType` enum from `passkey_types` is imported and used only in the API integration test helper `get_collected_client_data` to construct a valid sample (`ty: ClientDataType::Get`): [2](#0-1) 

There is no equivalent check anywhere in `types/src/transaction/webauthn.rs`, `types/src/transaction/authenticator.rs` (`AnySignature::verify` dispatches straight into `PartialAuthenticatorAssertionResponse::verify` without any pre/post ceremony-type check), or elsewhere in the transaction-admission stack (mempool, vm-validator, VM prologue). This is further corroborated by the repo's own `verify_real_partial_authenticator_assertion_response_from_spc` test, which supplies `"type": "payment.get"` (not `"webauthn.get"`) in `client_data_json` and asserts `verification_result.is_ok()`: [3](#0-2) 

That test is deliberately about SPC (`payment.get`) tolerance, but it demonstrates as a side effect that the `ty` field is fully unconstrained — nothing in the verification path distinguishes `webauthn.get` from `webauthn.create`, `payment.get`, or any other string value, as long as `challenge` and the signature check out.

### Impact Explanation
This breaks the intended WebAuthn ceremony-type invariant: assertions produced by the `Create` (registration) ceremony are not supposed to be usable in place of `Get` (authentication/assertion) ceremony signatures, per the WebAuthn spec. In Aptos's adaptation, the security model still relies on binding a specific challenge (the tx signing-message hash) and public key, which the code does correctly enforce — the `challenge` and signature checks are present and correctly bound to the raw transaction and public key. However, the missing `ty` check means the type invariant asserted by the "Exploit Question" (that admission accepts wrong ceremony type) is real: an attacker who possesses a signature/assertion generated under a `Create` ceremony context (or any arbitrarily-labeled `ty`) with the correct challenge and public key can still get the transaction admitted, since `ty` is decorative rather than enforced.

That said, per the Decision Standard, this must actually break sender/signer/replay/domain guarantees for an *unprivileged* attacker without a pre-existing valid signature. In this code, the attacker must still produce a valid secp256r1 signature over `authenticator_data || SHA256(client_data_json)` binding to the correct challenge/public key — i.e., they must control the actual private key (their own passkey) to sign the assertion; setting `ty = Create` does not let them forge a signature for someone else's key or bypass the challenge binding. So while the ceremony-type invariant is indeed missing/broken (a code-level correctness defect matching the exploit question exactly), it does not by itself let an attacker admit a transaction on behalf of another signer, replay a different signer's material, or otherwise cross a sender/signer/domain boundary for a key they do not control — the same key/signature holder is still required.

### Likelihood Explanation
High likelihood that the described input (correct challenge, correct signature, wrong `ty`) is accepted, since the code path clearly never reads `ty`. Any WebAuthn/passkey signer (self-controlled) can trivially construct such a payload and it will be admitted by mempool/API/VM validation just like a normal `Get`-type WebAuthn transaction, as shown by `verify_real_partial_authenticator_assertion_response_from_spc` already exercising a non-`webauthn.get` type successfully.

### Recommendation
Add an explicit check in `PartialAuthenticatorAssertionResponse::verify`/`verify_arbitrary_msg` that `collected_client_data.ty == ClientDataType::Get` (or the expected ceremony-specific type, allowing e.g. `payment.get` only where SPC support is intended), and reject the transaction otherwise, matching WebAuthn §7.2 assertion-verification requirements.

### Proof of Concept
Using the existing test utilities in `types/src/transaction/webauthn.rs` and `api/src/tests/webauthn_secp256r1_ecdsa.rs`:
1. Construct `CollectedClientData { ty: ClientDataType::Create, challenge: <SHA3-256 of raw txn signing message>, origin: ..., cross_origin: None, unknown_keys: Default::default() }`.
2. Serialize to `client_data_json`, compute `SHA256(client_data_json)`, sign `authenticator_data || SHA256(client_data_json)` with the sender's registered secp256r1 key (as `sign_webauthn_transaction` does in the test file [4](#0-3) ).
3. Wrap into `PartialAuthenticatorAssertionResponse`, `AnySignature::WebAuthn`, `SingleKeyAuthenticator`, `AccountAuthenticator::SingleKey`, `TransactionAuthenticator::SingleSender`.
4. Submit BCS-encoded `SignedTransaction` via `POST /transactions`.
5. Observe `verify()` still returns `Ok(())` because `ty` is never inspected, and the transaction is admitted with status 202, identical to the passing `test_webauthn_secp256r1_ecdsa` test flow.

### Citations

**File:** types/src/transaction/webauthn.rs (L134-165)
```rust
    pub fn verify<T: Serialize + CryptoHash>(
        &self,
        message: &T,
        public_key: &AnyPublicKey,
    ) -> Result<()> {
        let collected_client_data: CollectedClientData =
            serde_json::from_slice(self.client_data_json.as_slice())?;
        let challenge_bytes = Bytes::try_from(collected_client_data.challenge.as_str())
            .map_err(|e| anyhow!("Failed to decode challenge bytes {:?}", e))?;

        // Check if expected challenge and actual challenge match. If there's no match, throw error
        verify_expected_challenge_from_message_matches_actual(message, challenge_bytes.as_slice())?;

        // Generates binary concatenation of authenticator_data and hash(client_data_json)
        let verification_data = generate_verification_data(
            self.authenticator_data.as_slice(),
            self.client_data_json.as_slice(),
        );

        // Note: We must call verify_arbitrary_msg instead of verify here. We do NOT want to
        // use verify because it BCS serializes and prefixes the message with a hash
        // via the signing_message function invocation
        match (&public_key, &self.signature) {
            (
                AnyPublicKey::Secp256r1Ecdsa { public_key },
                AssertionSignature::Secp256r1Ecdsa { signature },
            ) => signature.verify_arbitrary_msg(&verification_data, public_key),
            _ => Err(anyhow!(
                "WebAuthn verification failure, invalid key, signature pairing"
            )),
        }
    }
```

**File:** types/src/transaction/webauthn.rs (L818-866)
```rust
        let collected_client_data_string = r#"
            {
              "type": "payment.get",
              "challenge": "eUf1aXwdtHKnIYUXkTgHxmWtYQ_U0c3O8Ldmx3PTA_g",
              "origin": "http://localhost:5173",
              "crossOrigin": false,
              "payment": {
                "rpId": "localhost",
                "topOrigin": "http://localhost:5173",
                "payeeOrigin": "https://localhost:4000",
                "total": {
                  "value": "1.01",
                  "currency": "APT"
                },
                "instrument": {
                  "icon": "https://aptoslabs.com/assets/favicon-2c9e23abc3a3f4c45038e8c784b0a4ecb9051baa.ico",
                  "displayName": "Petra test"
                }
              },
              "other_keys_can_be_added_here": "do not compare clientDataJSON against a template. See https://goo.gl/yabPex"
            }"#;

        let collected_client_data: CollectedClientData =
            serde_json::from_str(collected_client_data_string).unwrap();

        // Ensure the byte serialization is correct
        assert_eq!(
            collected_client_data_to_json_bytes(&collected_client_data),
            client_data_json
        );

        let signature: Vec<u8> = vec![
            254, 40, 71, 181, 216, 187, 97, 118, 196, 106, 251, 170, 106, 47, 184, 77, 174, 187,
            18, 135, 14, 184, 149, 146, 37, 80, 10, 37, 137, 187, 68, 84, 43, 29, 246, 120, 32, 23,
            254, 69, 228, 43, 148, 122, 244, 216, 183, 80, 139, 56, 12, 62, 195, 49, 97, 184, 185,
            170, 184, 138, 123, 39, 106, 237,
        ];
        let secp256r1_signature = Signature::try_from(signature.as_slice()).unwrap();

        let paar = PartialAuthenticatorAssertionResponse::new(
            AssertionSignature::Secp256r1Ecdsa {
                signature: secp256r1_signature,
            },
            authenticator_data,
            client_data_json,
        );

        let verification_result = paar.verify(&raw_txn, &any_public_key);
        assert!(verification_result.is_ok());
```

**File:** api/src/tests/webauthn_secp256r1_ecdsa.rs (L38-51)
```rust
    /// Given a `RawTransaction`, returns a test `CollectedClientData` struct
    fn get_collected_client_data(raw_transaction: &RawTransaction) -> CollectedClientData {
        let signing_message = signing_message(raw_transaction).unwrap();
        let sha3_256_raw_txn = HashValue::sha3_256_of(signing_message.as_slice());
        let sha3_256_raw_txn_bytes = Bytes::from(sha3_256_raw_txn.to_vec());

        CollectedClientData {
            ty: ClientDataType::Get,
            challenge: String::from(sha3_256_raw_txn_bytes),
            origin: "http://localhost:5173".to_string(),
            cross_origin: None,
            unknown_keys: Default::default(),
        }
    }
```

**File:** api/src/tests/webauthn_secp256r1_ecdsa.rs (L53-83)
```rust
    fn sign_webauthn_transaction(
        raw_txn: &RawTransaction,
        collected_client_data: CollectedClientData,
        authenticator_data: &[u8],
        private_key: &Secp256r1EcdsaPrivateKey,
    ) -> SignedTransaction {
        let public_key = Secp256r1EcdsaPublicKey::from(private_key);

        let client_data_json = serde_json::to_vec(&collected_client_data).unwrap();
        let client_data_hash = sha256(client_data_json.as_slice());

        let signature_material = [authenticator_data, &client_data_hash].concat();
        let signature = private_key.sign_arbitrary_message(signature_material.as_slice());
        let assertion_signature = AssertionSignature::Secp256r1Ecdsa { signature };

        let partial_authenticator_assertion_response = PartialAuthenticatorAssertionResponse::new(
            assertion_signature,
            authenticator_data.to_vec(),
            client_data_json,
        );
        let public_key = AnyPublicKey::Secp256r1Ecdsa { public_key };
        let signature = AnySignature::WebAuthn {
            signature: partial_authenticator_assertion_response,
        };
        let authenticator = SingleKeyAuthenticator::new(public_key, signature);
        let account_authenticator = AccountAuthenticator::SingleKey { authenticator };
        let txn_authenticator = TransactionAuthenticator::SingleSender {
            sender: account_authenticator,
        };
        SignedTransaction::new_signed_transaction(raw_txn.clone(), txn_authenticator)
    }
```
