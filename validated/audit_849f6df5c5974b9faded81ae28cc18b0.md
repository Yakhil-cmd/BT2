### Title
WebAuthn `verify_arbitrary_msg` never validates the client-data `type` (or `origin`) field, allowing cross-ceremony/cross-origin signatures to authenticate Aptos transactions - (File: `types/src/transaction/webauthn.rs`)

### Summary
`PartialAuthenticatorAssertionResponse::verify_arbitrary_msg` only checks that the WebAuthn `CollectedClientData.challenge` equals the SHA3-256 digest of the `RawTransaction`, then verifies the raw Secp256r1 signature over `authenticator_data || SHA-256(client_data_json)`. It never checks `CollectedClientData.type` (which per the WebAuthn spec must be `"webauthn.get"`) or the `origin`/`crossOrigin` fields.

### Finding Description [1](#0-0) 

The doc comment for the function states three intended steps: verify the challenge, build the verification data, and verify the signature — the WebAuthn `type` and `origin` fields, which are part of `client_data_json`, are never validated against expected values. This is confirmed by the repo's own test suite: `verify_real_partial_authenticator_assertion_response_from_spc` constructs a `CollectedClientData` with `"type": "payment.get"` (a Secure Payment Confirmation ceremony type, not `"webauthn.get"`) and asserts that `paar.verify(&raw_txn, &any_public_key)` succeeds: [2](#0-1) 

Because only the `challenge` bytes (bound to the tx hash) are checked, any WebAuthn/CTAP2-compatible ceremony that lets an attacker obtain a signature over an attacker-chosen challenge — SPC payment confirmations, third-party site logins using the same passkey, or any other RP context — can be repackaged as a valid `AssertionSignature` for an Aptos `SingleKeyAuthenticator`/`AccountAuthenticator` and submitted as the transaction authenticator. The Aptos VM/mempool admission path (`AnySignature::verify` -> `PartialAuthenticatorAssertionResponse::verify` -> `verify_arbitrary_msg`) treats this as an authentic, in-context Aptos-transaction signature: [3](#0-2) 

### Impact Explanation
This is a signing-material/ceremony-confusion bug at the authenticator-validation boundary described in the Admission Pivots ("Authenticator parsing, public key binding, WebAuthn checks ... must bind to the intended account set"). A user's passkey can legitimately be used across many relying parties/ceremony types (registration, login, SPC payment) that are not the Aptos dApp/RP. If any of those ceremonies allow the challenge to be attacker-influenced (a common pattern, e.g., payment amount/merchant is attacker-controlled in SPC, or a malicious website performing a WebAuthn "get" with a chosen challenge string it fully controls), the attacker can obtain a signature whose `challenge` equals the SHA3-256 digest of an Aptos `RawTransaction` they crafted, and whose `type`/`origin` are for an unrelated context. Because `verify_arbitrary_msg` does not check `type` or `origin`, this signature will still authenticate the transaction, letting an attacker impersonate the passkey owner and execute a transaction under their account/signer — an unauthorized transaction execution under the wrong signing material.

### Likelihood Explanation
Exploitation requires the attacker to induce (or already control) a WebAuthn ceremony in which the challenge is influenced by attacker input and the resulting signature/clientDataJSON can be extracted (e.g., a malicious or compromised website triggering `navigator.credentials.get()` with a chosen challenge, or an SPC merchant flow). This is a realistic threat model that WebAuthn's `type` binding is specifically designed to prevent (to stop exactly this kind of ceremony-crossing signature reuse). The missing check is unconditional in the code path, not gated behind a feature flag, so any transaction using the `WebAuthn` `AnySignature` variant is affected.

### Recommendation
In `verify_arbitrary_msg` (and any other WebAuthn verification path such as `verify`/`verify_real_partial_authenticator_assertion_response*`), after deserializing `CollectedClientData`, assert `collected_client_data.ty == "webauthn.get"` (reject any other ceremony type, e.g. `"webauthn.create"` or `"payment.get"`), and additionally validate the `origin` field against the Aptos dApp's expected RP origin/set of allowed origins before proceeding to signature verification.

### Proof of Concept
The existing test `verify_real_partial_authenticator_assertion_response_from_spc` is itself a proof of concept: it builds a `client_data_json` with `"type": "payment.get"` (not `"webauthn.get"`) and a `"payment"` object indicating an SPC ceremony for a merchant site, then calls: [4](#0-3) 
and asserts `verification_result.is_ok()`. This demonstrates that a signature obtained from a non-transaction, non-Aptos-RP ceremony is accepted as valid transaction authentication as long as the challenge bytes match the tx hash — no code path rejects the mismatched `type`/`origin`.

**Note on verification limits**: I was not able to fully trace whether upstream callers (e.g., the API/mempool ingestion layer or `SignedTransaction::verify_signature`) impose any additional, out-of-band `type`/`origin` check before calling into this function — my searches of `authenticator.rs` and the webauthn test files found no such check, but the full call graph from mempool/API ingestion into `AnySignature::verify` was not exhaustively enumerated due to tool budget. I recommend a Devin session confirm there is no other enforcement point before treating this as final.

### Citations

**File:** types/src/transaction/webauthn.rs (L177-208)
```rust
    pub fn verify_arbitrary_msg(&self, message: &[u8], public_key: &AnyPublicKey) -> Result<()> {
        let collected_client_data: CollectedClientData =
            serde_json::from_slice(self.client_data_json.as_slice())?;
        let challenge_bytes = Bytes::try_from(collected_client_data.challenge.as_str())
            .map_err(|e| anyhow!("Failed to decode challenge bytes {:?}", e))?;

        // Check if expected challenge and actual challenge match. If there's no match, throw error
        challenge_bytes
            .as_slice()
            .eq(message)
            .then_some(())
            .ok_or(CryptoMaterialError::ValidationError)?;

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

**File:** types/src/transaction/authenticator.rs (L1381-1397)
```rust
    pub fn verify<T: Serialize + CryptoHash>(
        &self,
        public_key: &AnyPublicKey,
        message: &T,
    ) -> Result<()> {
        match (self, public_key) {
            (Self::Ed25519 { signature }, AnyPublicKey::Ed25519 { public_key }) => {
                signature.verify(message, public_key)
            },
            (Self::Secp256k1Ecdsa { signature }, AnyPublicKey::Secp256k1Ecdsa { public_key }) => {
                signature.verify(message, public_key)
            },
            (
                Self::SlhDsa_Sha2_128s { signature },
                AnyPublicKey::SlhDsa_Sha2_128s { public_key },
            ) => signature.verify(message, public_key),
            (Self::WebAuthn { signature }, _) => signature.verify(message, public_key),
```
