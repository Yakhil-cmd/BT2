The investigation confirms the finding. Both `verify()` and `verify_arbitrary_msg()` on `PartialAuthenticatorAssertionResponse` deserialize `CollectedClientData` from `client_data_json` and only validate the `challenge` field against the expected transaction hash — the `ty` (`ClientDataType`) field is parsed but never compared against the expected `ClientDataType::Get` value anywhere in the verification path.

### Title
Missing WebAuthn `ClientDataType` enforcement allows attestation-ceremony ("webauthn.create") signatures to be accepted as transaction assertions - (File: types/src/transaction/webauthn.rs)

### Summary
`PartialAuthenticatorAssertionResponse::verify` and `verify_arbitrary_msg` parse `CollectedClientData` (including its `ty` field) from the attacker-supplied `client_data_json` bytes but never assert that `ty == ClientDataType::Get`, breaking the WebAuthn invariant that only assertion-ceremony (`authenticatorGetAssertion`) responses should authorize a signature.

### Finding Description
`PartialAuthenticatorAssertionResponse::verify` deserializes `CollectedClientData` from `self.client_data_json` and only validates:
1. `collected_client_data.challenge` equals the expected transaction-hash challenge [1](#0-0) 
2. The signature over `authenticator_data || SHA-256(client_data_json)` verifies against the public key [2](#0-1) 

Nowhere in `verify` or `verify_arbitrary_msg` is `collected_client_data.ty` checked against `ClientDataType::Get`. [3](#0-2)  The only reference to `.ty` in this file is in the serialization helper `collected_client_data_to_json_bytes`, which merely echoes back whatever `ty` value was supplied — it performs no enforcement. [4](#0-3) 

Per the WebAuthn spec (§7.2, step verifying `clientDataJSON.type === "webauthn.get"`), the relying party must check the ceremony type to ensure the credential response was produced for an *assertion* ceremony, not a *creation*/attestation ceremony or another type (e.g., `payment.get` for SPC). This codebase's own test suite even demonstrates it accepting a non-`webauthn.get` type (`payment.get`) as valid, confirming the check is absent by design/oversight. [5](#0-4) 

### Impact Explanation
The current architecture partially mitigates the practical exploitability: the challenge field is bound to the SHA3-256 hash of the raw transaction, and the public key used must match the account's authentication key. Because of this, an attacker without access to the private key/authenticator still cannot forge a valid signature — the underlying secp256r1 signature must be produced by the authenticator device that holds the private key regardless of what `type` string is embedded in `client_data_json`. However, the missing `ty` check means Aptos accepts a signature that was never actually intended to authorize a transaction (e.g. one produced during a `navigator.credentials.create()` / registration ceremony, or a `payment.get` Secure Payment Confirmation ceremony) as if it were a `navigator.credentials.get()` transaction-assertion signature. This corrupts the intended binding between the WebAuthn ceremony semantics and transaction authorization, which is a real deviation from spec-mandated relying-party verification, even though on this specific admission path it does not by itself allow an unprivileged attacker (without a valid private key or without inducing a legitimate signer into performing a different ceremony over the same challenge bytes) to forge a transaction from an arbitrary account.

### Likelihood Explanation
Exploitation requires convincing/tricking a legitimate device/authenticator holding the account's private key into producing a `webauthn.create`-typed (or other typed) response over the same `challenge` bytes used for a transaction — e.g. via a malicious relying party invoking `navigator.credentials.create()` with the transaction hash as the challenge, then repackaging the resulting attestation signature as an assertion. This is a cross-ceremony confusion primitive, not a pure "attacker with no secrets forges any transaction" primitive, but it does not require a leaked key or privileged signer — only inducing the legitimate signer's browser/authenticator into the wrong ceremony type, which is plausible in a phishing/malicious-dApp scenario.

### Recommendation
In `PartialAuthenticatorAssertionResponse::verify` and `verify_arbitrary_msg`, after deserializing `collected_client_data`, explicitly check `collected_client_data.ty == ClientDataType::Get` and return an error otherwise, consistent with WebAuthn §7.2 relying-party assertion verification requirements.

### Proof of Concept
Modify `get_collected_client_data` in `api/src/tests/webauthn_secp256r1_ecdsa.rs` to set `ty: ClientDataType::Create` instead of `ClientDataType::Get` [6](#0-5) , then run `test_webauthn_secp256r1_ecdsa`; the transaction is still accepted (HTTP 202) because `PartialAuthenticatorAssertionResponse::verify` never inspects `ty`. Equivalently, a unit test can call `paar.verify(&raw_txn, &any_public_key)` with a `CollectedClientData { ty: ClientDataType::Create, .. }` client_data_json and observe `verification_result.is_ok()` instead of the expected rejection, as shown by the existing SPC test that already demonstrates non-`Get` types passing verification. [7](#0-6)

### Citations

**File:** types/src/transaction/webauthn.rs (L139-145)
```rust
        let collected_client_data: CollectedClientData =
            serde_json::from_slice(self.client_data_json.as_slice())?;
        let challenge_bytes = Bytes::try_from(collected_client_data.challenge.as_str())
            .map_err(|e| anyhow!("Failed to decode challenge bytes {:?}", e))?;

        // Check if expected challenge and actual challenge match. If there's no match, throw error
        verify_expected_challenge_from_message_matches_actual(message, challenge_bytes.as_slice())?;
```

**File:** types/src/transaction/webauthn.rs (L147-164)
```rust
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
```

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

**File:** types/src/transaction/webauthn.rs (L466-472)
```rust
    fn collected_client_data_to_json_bytes(ccd: &CollectedClientData) -> Vec<u8> {
        let mut result: Vec<u8> = Vec::new();

        // Append {"type":
        result.extend(b"{\"type\":");
        // Append type value
        result.extend(ccd_to_string(ccd.ty.to_string().as_str()));
```

**File:** types/src/transaction/webauthn.rs (L818-838)
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
```

**File:** types/src/transaction/webauthn.rs (L857-867)
```rust
        let paar = PartialAuthenticatorAssertionResponse::new(
            AssertionSignature::Secp256r1Ecdsa {
                signature: secp256r1_signature,
            },
            authenticator_data,
            client_data_json,
        );

        let verification_result = paar.verify(&raw_txn, &any_public_key);
        assert!(verification_result.is_ok());
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
