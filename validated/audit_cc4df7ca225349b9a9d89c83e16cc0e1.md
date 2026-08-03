### Title
WebAuthn `PartialAuthenticatorAssertionResponse::verify` never validates the ceremony `type` field, allowing non-assertion (`webauthn.create`/other) `client_data_json` to be accepted as a transaction authenticator - (File: `types/src/transaction/webauthn.rs`)

### Summary
The exploit question cites `types/src/account_config/resources/coin_store.rs`, which is unrelated to WebAuthn/authenticator logic and contains no such code; this citation is incorrect. The real, relevant code lives in `types/src/transaction/webauthn.rs`. Investigating that file confirms the substance of the claim: `PartialAuthenticatorAssertionResponse::verify` and `verify_arbitrary_msg` never check `CollectedClientData.ty` (the WebAuthn ceremony "type" field, e.g. `"webauthn.get"` vs `"webauthn.create"`) before accepting a signature as valid.

### Finding Description
`PartialAuthenticatorAssertionResponse::verify` [1](#0-0)  parses `client_data_json` into a `CollectedClientData`, checks only that the `challenge` field's SHA3-256 matches the expected transaction hash [2](#0-1) , then verifies the signature over `authenticator_data || SHA256(client_data_json)` [3](#0-2) . At no point is `collected_client_data.ty` compared against `ClientDataType::Get` ("webauthn.get"). The same omission exists in `verify_arbitrary_msg` [4](#0-3) . A grep across the codebase for `ClientDataType`/ceremony-type validation confirms this check exists only in test code (`api/src/tests/webauthn_secp256r1_ecdsa.rs`), not in the production verification path.

This is wired into the standard transaction-admission path: `AccountAuthenticator::verify` dispatches `Self::WebAuthn { signature } => signature.verify(message, public_key)` unconditionally for any public key type [5](#0-4) , and this authenticator can be used as a `SingleKeyAuthenticator` inside `TransactionAuthenticator::SingleSender`, as shown in the test harness that constructs and submits a WebAuthn-authenticated `SignedTransaction` [6](#0-5) .

So, technically: since only `challenge` (and signature) are validated, a `client_data_json` with `"type":"webauthn.create"` (or any other string) and a correct `challenge`/signature pairing would pass `verify()`.

### Impact Explanation
This is a genuine missing-invariant bug: the WebAuthn spec (§7.2, assertion verification) requires that the ceremony `type` be checked to equal `"webauthn.get"` to prevent cross-ceremony signature reuse (registration/attestation signatures being replayed as assertions, or vice versa). Its absence weakens the WebAuthn authenticator's binding guarantees.

However, exploitability requires the very specific precondition stated in the question: an attacker must already possess a signature, produced by the victim's *credential private key*, over the exact byte string `authenticator_data || SHA256(client_data_json)` where `challenge` inside that `client_data_json` equals SHA3-256(signing_message(attacker's chosen raw_txn)). In a normal WebAuthn attestation/registration ceremony, the attestation signature is typically produced by an attestation key (not necessarily the newly-created credential's private key), and the challenge in a registration ceremony is a server-issued registration challenge, not attacker-controlled to match an arbitrary future transaction's hash. Only in specific self-attestation configurations would the credential private key sign attestation data directly, and even then the attacker would need to have arranged for the victim's registration challenge to equal the transaction hash — which is not "capturing an unrelated registration ceremony" as casually assumed, but requires influencing that ceremony's challenge value. The question's framing understates this precondition significantly.

### Likelihood Explanation
Low-to-moderate. The missing `ty` check is real and should be fixed as defense-in-depth, but the specific proof-of-concept scenario described (capturing an "unrelated" attestation response and replaying it as a valid assertion for an attacker-chosen transaction) does not have a realistic unprivileged attack path under normal WebAuthn ceremonies, because the challenge binding (SHA3-256 of the raw transaction) would not naturally appear as the challenge of an unrelated registration ceremony unless the attacker already controls what challenge the victim's client requests during registration — which is not a standard unprivileged capability in this codebase's WebAuthn flow.

### Recommendation
Add validation that `collected_client_data.ty == ClientDataType::Get` inside `PartialAuthenticatorAssertionResponse::verify` and `verify_arbitrary_msg` in `types/src/transaction/webauthn.rs`, before accepting the challenge and signature check, matching WebAuthn §7.2 step requirements. This closes the theoretical ceremony-type confusion gap even though a fully realistic unprivileged exploit chain for cross-ceremony signature admission was not demonstrated within the transaction-admission boundary.

### Proof of Concept
Not constructible as a fully unprivileged, self-contained admission exploit given current findings: doing so requires the attacker to already control or predict the `challenge` value used in an unrelated victim registration ceremony to equal `SHA3-256(signing_message(raw_txn))` for an attacker-chosen `raw_txn`, which is outside the "unprivileged transaction/authenticator input" boundary defined by this review. The missing `ty` field check itself is directly demonstrable by unit-testing `verify()` with a `client_data_json` containing `"type":"webauthn.create"` but a correct `challenge`/`signature` — this would currently pass `verify()`, confirming the code-level gap, but does not by itself demonstrate cross-ceremony key material becoming available to an unprivileged attacker for a chosen victim account.

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

**File:** types/src/transaction/authenticator.rs (L1397-1397)
```rust
            (Self::WebAuthn { signature }, _) => signature.verify(message, public_key),
```

**File:** api/src/tests/webauthn_secp256r1_ecdsa.rs (L68-83)
```rust
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
