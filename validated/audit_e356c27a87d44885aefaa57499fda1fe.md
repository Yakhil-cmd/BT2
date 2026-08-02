No vulnerability found for this question.

**Reasoning:**

The exploit theory conflates two unrelated layers. `CreateCollection` in `types/src/account_config/events/create_collection.rs` is a pure event-data struct that mirrors what the Move framework already emitted; it does not perform any authentication or approval-set logic itself [1](#0-0) . The `creator` field is populated inside `token::create_collection` directly from `signer::address_of(creator)`, where `creator: &signer` is a capability the Move VM only produces after admission-time signature/authentication-key checks have already succeeded [2](#0-1) .

The actual admission-time binding an attacker would need to break is enforced far upstream, independent of this event struct:

1. `AccountAuthenticator::authentication_key()` derives the auth key as a hash of the exact public key bytes (and threshold, for MultiEd25519) supplied in the authenticator [3](#0-2) . If an attacker substitutes a different set of keys, this derived key will not match the account's on-chain registered authentication key, and the transaction is rejected before execution — it cannot be bound to the wrong "creator" address.
2. Even holding the address fixed, `MultiEd25519Signature::verify_arbitrary_msg` independently enforces that the bitmap's popcount meets the threshold and that each set bit's signature verifies against the corresponding public key at that exact index in the registered multisig key list [4](#0-3) . Supplying keys/signatures for indices that don't correspond to the actual registered key set fails this per-index verification, as confirmed by existing unit tests showing that verification fails when public keys are reordered, wrong-indexed, or replaced [5](#0-4) [6](#0-5) .
3. The API-layer `VerifyInput` for `MultiEd25519Signature` additionally enforces threshold/key/signature count and length invariants before any BCS/JSON-submitted signature reaches the VM [7](#0-6) .

Because the authentication-key derivation, per-key signature verification, and threshold/bitmap checks all independently require the exact registered public-key set to succeed, an attacker cannot get a transaction admitted with a signature threshold "satisfied by keys not part of the on-chain registered multisig public key." The proposed proof idea (constructing such a signature and asserting `verify` returns an error) actually demonstrates the system working as intended — `signature.verify()` returning an error is the expected, correct outcome, not a vulnerability. There is no admission-boundary defect here.

### Citations

**File:** types/src/account_config/events/create_collection.rs (L16-23)
```rust
#[derive(Debug, Deserialize, Serialize)]
pub struct CreateCollection {
    creator: AccountAddress,
    collection_name: String,
    uri: String,
    description: String,
    maximum: u64,
}
```

**File:** aptos-move/framework/aptos-token/sources/token.move (L1119-1170)
```text
    public fun create_collection(
        creator: &signer,
        name: String,
        description: String,
        uri: String,
        maximum: u64,
        mutate_setting: vector<bool>
    ) acquires Collections {
        assert!(name.length() <= MAX_COLLECTION_NAME_LENGTH, error::invalid_argument(ECOLLECTION_NAME_TOO_LONG));
        assert!(uri.length() <= MAX_URI_LENGTH, error::invalid_argument(EURI_TOO_LONG));
        let account_addr = signer::address_of(creator);
        if (!exists<Collections>(account_addr)) {
            move_to(
                creator,
                Collections {
                    collection_data: table::new(),
                    token_data: table::new(),
                    create_collection_events: account::new_event_handle<CreateCollectionEvent>(creator),
                    create_token_data_events: account::new_event_handle<CreateTokenDataEvent>(creator),
                    mint_token_events: account::new_event_handle<MintTokenEvent>(creator),
                },
            )
        };

        let collection_data = &mut Collections[account_addr].collection_data;

        assert!(
            !collection_data.contains(name),
            error::already_exists(ECOLLECTION_ALREADY_EXISTS),
        );

        let mutability_config = create_collection_mutability_config(&mutate_setting);
        let collection = CollectionData {
            description,
            name,
            uri,
            supply: 0,
            maximum,
            mutability_config
        };

        collection_data.add(name, collection);
        event::emit(
            CreateCollection {
                creator: account_addr,
                collection_name: name,
                uri,
                description,
                maximum,
            }
        );
    }
```

**File:** types/src/transaction/authenticator.rs (L879-888)
```rust
    /// (V1 Abstract, NoAccountAuthenticator).
    pub fn authentication_key(&self) -> Option<AuthenticationKey> {
        match self {
            Self::Ed25519 { .. }
            | Self::MultiEd25519 { .. }
            | Self::SingleKey { .. }
            | Self::MultiKey { .. } => Some(AuthenticationKey::from_preimage(
                self.public_key_bytes(),
                self.scheme(),
            )),
```

**File:** third_party/move/move-examples/diem-framework/crates/crypto/src/multi_ed25519.rs (L509-543)
```rust
    fn verify_arbitrary_msg(
        &self,
        message: &[u8],
        public_key: &MultiEd25519PublicKey,
    ) -> Result<()> {
        // Public keys should be validated to be safe against small subgroup attacks, etc.
        precondition!(has_tag!(public_key, ValidatedPublicKeyTag));
        match bitmap_last_set_bit(self.bitmap) {
            Some(last_bit) if last_bit as usize <= public_key.length() => (),
            _ => {
                return Err(anyhow!(
                    "{}",
                    CryptoMaterialError::BitVecError("Signature index is out of range".to_string())
                ))
            },
        };
        if bitmap_count_ones(self.bitmap) < public_key.threshold as u32 {
            return Err(anyhow!(
                "{}",
                CryptoMaterialError::BitVecError(
                    "Not enough signatures to meet the threshold".to_string()
                )
            ));
        }
        let mut bitmap_index = 0;
        // TODO use deterministic batch verification when gets available.
        for sig in &self.signatures {
            while !bitmap_get_bit(self.bitmap, bitmap_index) {
                bitmap_index += 1;
            }
            sig.verify_arbitrary_msg(message, &public_key.public_keys[bitmap_index])?;
            bitmap_index += 1;
        }
        Ok(())
    }
```

**File:** crates/aptos-crypto/src/unit_tests/multi_ed25519_test.rs (L297-306)
```rust
    // Verifying a 7-of-10 signature against a reordered MultiEd25519PublicKey should fail.
    // To deterministically simulate reshuffling, we use a reversed vector of 10 keys.
    // Note that because 10 is an even number, all of they keys will change position.
    let mut pub_keys_10_reversed = pub_keys_10;
    pub_keys_10_reversed.reverse();
    let multi_public_key_7of10_reversed =
        MultiEd25519PublicKey::new(pub_keys_10_reversed, 7).unwrap();
    assert!(multi_signature_7of10
        .verify(message(), &multi_public_key_7of10_reversed)
        .is_err());
```

**File:** crates/aptos-crypto/src/unit_tests/multi_ed25519_test.rs (L328-336)
```rust
    // Signing with the 2nd key but using wrong index will fail.
    let sig_with_2nd_key = priv_keys_3[1].sign(message()).unwrap();
    let multi_sig_signed_by_2nd_key_wrong_index =
        MultiEd25519Signature::new(vec![(sig_with_2nd_key.clone(), 2)]);
    assert!(multi_sig_signed_by_2nd_key_wrong_index.is_ok());
    let failed_multi_sig_signed_by_2nd_key_wrong_index = multi_sig_signed_by_2nd_key_wrong_index
        .unwrap()
        .verify(message(), &multi_public_key_1of3);
    assert!(failed_multi_sig_signed_by_2nd_key_wrong_index.is_err());
```

**File:** api/types/src/transaction.rs (L1608-1653)
```rust
impl VerifyInput for MultiEd25519Signature {
    fn verify(&self) -> anyhow::Result<()> {
        if self.public_keys.is_empty() {
            bail!("MultiEd25519 signature has no public keys")
        } else if self.signatures.is_empty() {
            bail!("MultiEd25519 signature has no signatures")
        } else if self.public_keys.len() > MAX_NUM_OF_KEYS {
            bail!(
                "MultiEd25519 signature has over the maximum number of public keys {}",
                MAX_NUM_OF_KEYS
            )
        } else if self.signatures.len() > MAX_NUM_OF_SIGS {
            bail!(
                "MultiEd25519 signature has over the maximum number of signatures {}",
                MAX_NUM_OF_SIGS
            )
        } else if self.public_keys.len() != self.signatures.len() {
            bail!(
                "MultiEd25519 signature does not have the same number of signatures as public keys"
            )
        } else if self.signatures.len() < self.threshold as usize {
            bail!("MultiEd25519 signature does not have enough signatures to pass the threshold")
        } else if self.threshold == 0 {
            bail!("MultiEd25519 signature threshold must be greater than 0")
        }
        for signature in self.signatures.iter() {
            if signature.inner().len() != ED25519_SIGNATURE_LENGTH {
                bail!("MultiEd25519 signature has a signature with the wrong signature length")
            }
        }
        for public_key in self.public_keys.iter() {
            if public_key.inner().len() != ED25519_PUBLIC_KEY_LENGTH {
                bail!("MultiEd25519 signature has a public key with the wrong public key length")
            }
        }

        if self.bitmap.inner().len() != BITMAP_NUM_OF_BYTES {
            bail!(
                "MultiEd25519 signature has an invalid number of bitmap bytes {} expected {}",
                self.bitmap.inner().len(),
                BITMAP_NUM_OF_BYTES
            );
        }

        Ok(())
    }
```
