The file path in the question (`crates/aptos-crypto/src/secp256r1_ecdsa/secp256r1_ecdsa_keys.rs`) does not contain this logic. The actual `verify()` and `client_data_json` parsing live in `types/src/transaction/webauthn.rs`, in `PartialAuthenticatorAssertionResponse::verify` [1](#0-0) . I confirmed the code there and the finding is real, so I'm reporting it against the correct location.

### Title
Missing WebAuthn `type` (ceremony) validation in `PartialAuthenticatorAssertionResponse::verify` allows cross-ceremony signature confusion - (File: types/src/transaction/webauthn.rs)

### Summary
`PartialAuthenticatorAssertionResponse::verify` and `verify_arbitrary_msg` parse the `client_data_json` blob into a `CollectedClientData` struct but only validate the `challenge` field against the expected transaction digest, and never check `collected_client_data.ty` against `ClientDataType::Get`. [2](#0-1) 

### Finding Description
Per WebAuthn §6.3.3 `authenticatorGetAssertion` verification, a relying party MUST check that `response.type` equals `"webauthn.get"` before accepting an assertion. This is a domain-separation control: for authenticators using self-attestation (e.g. "packed" format with `aaguid = 0`), the *registration* ceremony (`navigator.credentials.create()`, `type = "webauthn.create"`) also produces a signature computed over `authenticatorData || SHA-256(clientDataJSON)` using the same credential private key as later assertions. Without checking `ty`, a signed blob generated during a registration ceremony (with an attacker/dApp-controlled challenge set to the raw transaction's SHA3-256 digest) can be replayed and accepted by Aptos as a valid transaction-authorizing assertion.

The Aptos code confirms `ty` is never checked anywhere in the verification path:
- `verify()` only calls `verify_expected_challenge_from_message_matches_actual` on the challenge, then builds `verification_data` and checks the signature — no `ty` comparison. [3](#0-2) 
- `verify_arbitrary_msg()` has the identical omission. [4](#0-3) 
- The repo's own test suite demonstrates this: the `verify_real_partial_authenticator_assertion_response_from_spc` test constructs a `CollectedClientData` with `"type": "payment.get"` (not `"webauthn.get"`) and asserts `paar.verify(...)` succeeds, proving `ty` is not enforced by design/implementation. [5](#0-4) 

This is invoked from account authenticator verification via `AnySignature::WebAuthn` in `AptosVM`/`SingleKeyAuthenticator`, which is on the transaction admission/signature-verification path. [6](#0-5) 

### Impact Explanation
Under the admission-boundary gate, this is a WebAuthn authenticator validation gap: the check that should bind the authorization to a genuine `"webauthn.get"` (spend/assertion) ceremony is missing, so a signed blob produced for a different ceremony purpose (registration) can be admitted as a transaction authorization. This breaks the WebAuthn domain-separation invariant, though it still requires possession of the account-bound private key/credential (not a full unauthorized-signer bypass) — exploitation depends on an attacker being able to induce a registration ceremony with an attacker-chosen challenge equal to the target raw-transaction digest, and on the authenticator using self-attestation (packed, `aaguid=0`) so the same private key signs both ceremonies identically.

### Likelihood Explanation
Requires: (1) the account owner's authenticator to use self-attestation (not all authenticators do; many use `"none"` or batch attestation with a separate attestation key, in which case there is no reusable signature at all), and (2) some flow (e.g. a malicious or compromised dApp requesting `navigator.credentials.create()`) that lets an attacker set the WebAuthn `challenge` to the SHA3-256 digest of an arbitrary raw transaction and capture the resulting response. This is a non-trivial but plausible phishing/UX-confusion chain rather than a pure cryptographic forgery.

### Recommendation
In `PartialAuthenticatorAssertionResponse::verify` and `verify_arbitrary_msg`, after deserializing `CollectedClientData`, explicitly assert `collected_client_data.ty == ClientDataType::Get` and return an error otherwise, matching WebAuthn §6.3.3 step requirements.

### Proof of Concept
1. Construct a `CollectedClientData` with `ty: ClientDataType::Create` (or any non-`Get` string) and `challenge` set to the base64url encoding of `SHA3-256(signing_message(raw_txn))`, matching the pattern used in the existing test helper `get_collected_client_data`. [7](#0-6) 
2. Serialize to `client_data_json`, obtain (or simulate, for a self-attestation authenticator) a signature over `authenticator_data || SHA-256(client_data_json)` with the account's bound secp256r1 key.
3. Build `PartialAuthenticatorAssertionResponse::new(signature, authenticator_data, client_data_json)` and call `.verify(&raw_txn, &any_public_key)`. [1](#0-0) 
4. Observe verification succeeds despite `ty != "webauthn.get"`, as already demonstrated by the existing `"payment.get"` test case in the codebase. [5](#0-4)

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

**File:** aptos-move/aptos-vm/src/aptos_vm.rs (L1-1)
```rust
// Copyright (c) Aptos Foundation
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
