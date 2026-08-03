## Finding: WebAuthn `verify()` Never Validates the `type` Field of `client_data_json`

### Summary
`PartialAuthenticatorAssertionResponse::verify()` in `types/src/transaction/webauthn.rs` deserializes `client_data_json` into a `CollectedClientData` struct and only checks the `challenge` field against the expected SHA3-256 digest of the raw transaction. The `ty` (ceremony `type`) field of `CollectedClientData` — which per the WebAuthn spec must be `"webauthn.get"` for assertions (as opposed to `"webauthn.create"` for attestations) — is deserialized but **never validated**.

### Finding Description
The `verify` function is: [1](#0-0) 

It performs exactly three checks:
1. Deserialize `client_data_json` into `CollectedClientData` [2](#0-1) 
2. Verify `challenge` equals SHA3-256 of the signing message of the raw transaction [3](#0-2) 
3. Verify the ECDSA signature over `authenticator_data || SHA-256(client_data_json)` [4](#0-3) 

`collected_client_data.ty` (the `ClientDataType` field mapped from JSON `"type"`) is parsed as part of `CollectedClientData` but is never read or compared against `ClientDataType::Get` anywhere in `verify()`, nor anywhere else in this file — confirmed by grepping for `ClientDataType`/`CollectedClientData` usage in the file, which shows only the deserialization call itself and test-helper construction sites (e.g. `ty: ClientDataType::Get` set only when *constructing* test fixtures) [5](#0-4) .

Because the challenge is bound to the exact SHA3-256 hash of the specific raw transaction, an attacker cannot trivially reuse an arbitrary attestation response for a different transaction — the `challenge` must equal that specific transaction's hash. However, this does not eliminate the missing-validation defect: the WebAuthn ceremony type binding is a distinct security invariant (assertion vs. attestation context) that the code claims to implement (per WebAuthn §6.3.3 comments) but does not enforce. If a user's authenticator/client library is ever tricked into producing (or if a malicious/compromised client-side signing library produces) a `clientDataJSON` with `type: "webauthn.create"` but a `challenge` equal to the transaction hash and a valid signature over `authenticatorData || SHA256(clientDataJSON)`, `verify()` will accept it as a valid transaction signature.

### Impact Explanation
This breaks the ceremony-type invariant that WebAuthn relies on to segregate registration (attestation) signing contexts from assertion (transaction-signing) contexts. While the strict challenge-binding to the exact transaction hash substantially limits real-world exploitability (an attacker cannot simply replay a captured attestation from an "unrelated registration ceremony" without also controlling the challenge value used during that ceremony), the missing type check is still a genuine spec-compliance gap: the code's own doc comments assert this follows WebAuthn §6.3.3, which does mandate this check, and any code path or authenticator implementation (including future changes, non-standard clients, or malicious relying-party-controlled challenge injection during a WebAuthn-based passkey provisioning flow) that allows challenge values to be attacker/victim-influenced during an attestation ceremony would let that signature be replayed as a transaction authenticator.

### Likelihood Explanation
Exploitability is gated by the requirement that the attacker-controlled `challenge` in the captured attestation ceremony must equal the exact SHA3-256 digest of a specific `RawTransaction` the attacker wants to submit. Under the standard WebAuthn attestation flow, `challenge` is normally server-generated randomness, not attacker-chosen, so this is not trivially exploitable in the default flow, but the underlying missing validation is confirmed and is a genuine deviation from spec.

### Recommendation
Add a check in `PartialAuthenticatorAssertionResponse::verify()` that `collected_client_data.ty == ClientDataType::Get` and return a validation error otherwise, matching the codebase's own documented intent to follow WebAuthn §6.3.3 `authenticatorGetAssertion` semantics.

### Proof of Concept
Construct a `PartialAuthenticatorAssertionResponse` with:
- `client_data_json` containing `"type":"webauthn.create"` instead of `"type":"webauthn.get"`, but `challenge` set to the correct SHA3-256 digest of the target `RawTransaction`'s signing message, and `origin` matching what a real client would send
- A valid `authenticator_data` and secp256r1 ECDSA signature over `authenticator_data || SHA256(client_data_json)`

Then call `paar.verify(&raw_txn, &any_public_key)` as in the existing test `verify_partial_authenticator_assertion_response` [6](#0-5)  — replacing `ClientDataType::Get` with an attestation-type value in the constructed `CollectedClientData` — and observe `verify()` still returns `Ok(())`, confirming the type field is not checked.

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

**File:** types/src/transaction/webauthn.rs (L671-714)
```rust
    /// `PartialAuthenticatorAssertionResponse` verification.
    #[tokio::test]
    async fn verify_partial_authenticator_assertion_response() {
        let (.., sender_address) = generate_sender();
        let (raw_txn, _raw_txn_signing_message, challenge) =
            generate_random_challenge_data(sender_address);

        // Assert challenge is 32 bytes -> SHA3-256(hash prefix + BCS encoded raw txn)
        assert_eq!(challenge.len(), 32);

        let (.., p256_pub_key, auth_pub_key_cred) =
            registration_helper(challenge.clone()).await.unwrap();
        let any_public_key = AnyPublicKey::Secp256r1Ecdsa {
            public_key: p256_pub_key,
        };

        let webauthn_p256_signature =
            secp256r1_der_to_signature(auth_pub_key_cred.response.signature).unwrap();
        let canonical_webauthn_p256_signature = Signature::make_canonical(&webauthn_p256_signature);

        let webauthn_signature = AssertionSignature::Secp256r1Ecdsa {
            signature: canonical_webauthn_p256_signature,
        };
        let authenticator_data = auth_pub_key_cred
            .response
            .authenticator_data
            .as_slice()
            .to_vec();
        let client_data_json = auth_pub_key_cred
            .response
            .client_data_json
            .as_slice()
            .to_vec();

        // Partial Authenticator Assertion Response
        let paar = PartialAuthenticatorAssertionResponse::new(
            webauthn_signature,
            authenticator_data,
            client_data_json,
        );

        let verification = paar.verify(&raw_txn, &any_public_key);
        assert!(verification.is_ok());
    }
```

**File:** api/src/tests/webauthn_secp256r1_ecdsa.rs (L44-50)
```rust
        CollectedClientData {
            ty: ClientDataType::Get,
            challenge: String::from(sha3_256_raw_txn_bytes),
            origin: "http://localhost:5173".to_string(),
            cross_origin: None,
            unknown_keys: Default::default(),
        }
```
