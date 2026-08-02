### Title
MultiKey / MultiEd25519 k-of-n authenticators accept duplicate public keys, letting a single private key satisfy the signature threshold - (File: `types/src/transaction/authenticator.rs`, `aptos-move/framework/aptos-stdlib/sources/cryptography/multi_key.move`)

### Summary
`MultiKey::new` (Rust, `types/src/transaction/authenticator.rs:1240-1264`) and `multi_key::new_multi_key_from_single_keys`/`deserialize_multi_key` (Move, `aptos-move/framework/aptos-stdlib/sources/cryptography/multi_key.move:58-81`) construct a k-of-n multi-key public key from an arbitrary vector of `AnyPublicKey`s and a threshold, without checking that the public keys are distinct. `MultiKeyAuthenticator::verify` (`types/src/transaction/authenticator.rs:1201-1207`) and `to_single_key_authenticators` (lines 1167-1199) only check that the number of signature-bitmap slots filled meets `signatures_required`; nothing requires those slots to reference *different* underlying keys. If the same public key appears more than once in the `public_keys` vector, one private key can produce a valid signature that is reused to fill two (or more) bitmap slots, satisfying an "M-of-N" threshold with fewer than M distinct signers.

### Finding Description
This mirrors the external report's bug class: an admission check that is supposed to require independent authorization from a threshold set can be satisfied by a single controlled actor abusing an unvalidated invariant in the approval-set construction (the ERC1155 bug let a callback substitute for a real balance authorization; here, key duplication lets one signature substitute for two required approvals).

- `types/src/transaction/authenticator.rs:1241-1264` (`MultiKey::new`) only validates `signatures_required > 0`, `public_keys.len() <= MAX_NUM_OF_SIGS`, and `public_keys.len() >= signatures_required`. It never checks `public_keys` for duplicates. [1](#0-0) 

- `MultiKeyAuthenticator::to_single_key_authenticators` (lines 1167-1199) and `verify` (1201-1207) build one `SingleKeyAuthenticator` per set bit in the bitmap and independently verify each one against the corresponding index's public key. There is no check that the indices resolved to distinct public keys. [2](#0-1) 

- The project's own unit test `verify_multi_key_auth` demonstrates this exact behavior: a `MultiKey` is constructed with `keys = [sender0_pub, sender1_pub, sender1_pub]` and `threshold = 2`. An authenticator is then built with `(1, signature1)` and `(2, signature1)` — i.e. the *same* `sender1` signature reused for indices 1 and 2 — and `signed_txn.verify_signature()` succeeds, proving a 2-of-3 threshold is satisfied by one private key (`sender1`) alone. [3](#0-2) [4](#0-3) 

- By contrast, `multisig_account.move`'s `validate_owners` explicitly rejects duplicate owners (`EDUPLICATE_OWNER`), showing the framework is aware that "distinct signer" is a necessary security invariant for k-of-n schemes elsewhere in the codebase — this invariant is simply missing for `MultiKey`/`MultiEd25519` authenticator construction. [5](#0-4) 

The same class of gap exists on the `MultiEd25519Signature`/`MultiEd25519PublicKey` path: `verify_arbitrary_msg` (`crates/aptos-crypto/src/multi_ed25519.rs:511-558`) only checks bitmap-count vs. threshold and does not require the underlying public keys referenced by set bits to be distinct. [6](#0-5) 

### Impact Explanation
An account's authentication key is derived by hashing the full `MultiKey`/`MultiEd25519PublicKey` (including duplicated entries) plus a scheme byte (`multi_key::to_authentication_key`, `multi_key.move:83-88`). Anyone constructing such a key with intentional duplicates (or anyone who, via key rotation flows such as `rotate_authentication_key_from_public_key` in `account.move`, ends up with a duplicate entry) creates an address whose advertised "M-of-N, requires M distinct approvers" security guarantee is false: a single controller of one duplicated key can authenticate transactions that should require cooperation of at least M parties. This breaks the authenticator/approval-set binding invariant called out in the Admission Pivots ("Authenticator ... multisig ... approval validation accepting the wrong signing material or wrong approval set"), leading to unauthorized transaction execution under a sender identity that was supposed to require independent multi-party authorization.

### Likelihood Explanation
Exploitation requires that a duplicate-key `MultiKey`/`MultiEd25519` account exists (either created deliberately by a malicious/careless account owner, produced by a wallet/SDK bug, or resulting from a key-rotation operation that doesn't dedupe). Since account creation and key rotation to `MultiKey`/`MultiEd25519` public keys are entirely user-controlled and unprivileged (`account::rotate_authentication_key_from_public_key`, `account.move:462-482`), and no validation anywhere in the stack (Rust `MultiKey::new`, Move `multi_key.move`, or verification code) rejects duplicates, this is trivially reachable by any unprivileged account. The main limiting factor is that most legitimate wallets would not intentionally create duplicate-key multisigs, but nothing prevents a malicious party from presenting such a configuration as a genuine "M-of-N" account to counterparties (e.g., in custody/escrow setups) while secretly retaining unilateral control.

### Recommendation
Add duplicate-key rejection to `MultiKey` construction in both the Rust type (`types/src/transaction/authenticator.rs::MultiKey::new`) and the Move module (`aptos_std::multi_key::new_multi_key_from_single_keys` and `deserialize_multi_key`), analogous to `multisig_account::validate_owners`'s `EDUPLICATE_OWNER` check. Apply the same fix to `MultiEd25519PublicKey` construction/verification (`crates/aptos-crypto/src/multi_ed25519.rs`) to ensure no two entries in the public-key list are identical. Because `deserialize_multi_key` is also used to parse public keys directly from bytes (including on-chain authentication keys), consider whether this should be a consensus-breaking validation added behind a feature flag, since existing on-chain accounts might already have duplicate-key configurations.

### Proof of Concept
The existing test `verify_multi_key_auth` in `types/src/transaction/authenticator.rs` is itself a working PoC:
1. Construct `MultiKey::new(vec![sender0_pub, sender1_pub, sender1_pub], 2)` — a "2-of-3" key where `sender1`'s key occupies both index 1 and index 2.
2. Derive the account address from this `MultiKey` via `AuthenticationKey::multi_key`.
3. Build a `MultiKeyAuthenticator` with signatures `[(1, sig_from_sender1), (2, sig_from_sender1)]` — both produced by signing with the single `sender1` private key.
4. `signed_txn.verify_signature()` succeeds (`types/src/transaction/authenticator.rs:1930-1932`), proving the "2-of-3" threshold was met using only one distinct private key, with `sender0`'s cooperation never required. [7](#0-6)

### Citations

**File:** types/src/transaction/authenticator.rs (L1167-1207)
```rust
    pub fn to_single_key_authenticators(&self) -> Result<Vec<SingleKeyAuthenticator>> {
        ensure!(
            self.signatures_bitmap.last_set_bit().is_some(),
            "There were no signatures set in the bitmap."
        );

        ensure!(
            (self.signatures_bitmap.last_set_bit().unwrap() as usize) < self.public_keys.len(),
            "Mismatch in the position of the last signature and the number of PKs, {} >= {}.",
            self.signatures_bitmap.last_set_bit().unwrap(),
            self.public_keys.len(),
        );
        ensure!(
            self.signatures_bitmap.count_ones() as usize == self.signatures.len(),
            "Mismatch in number of signatures and the number of bits set in the signatures_bitmap, {} != {}.",
            self.signatures_bitmap.count_ones(),
            self.signatures.len(),
        );
        ensure!(
            self.signatures.len() >= self.public_keys.signatures_required() as usize,
            "Not enough signatures for verification, {} < {}.",
            self.signatures.len(),
            self.public_keys.signatures_required(),
        );
        let authenticators: Vec<SingleKeyAuthenticator> =
            std::iter::zip(self.signatures_bitmap.iter_ones(), self.signatures.iter())
                .map(|(idx, sig)| SingleKeyAuthenticator {
                    public_key: self.public_keys.public_keys[idx].clone(),
                    signature: sig.clone(),
                })
                .collect();
        Ok(authenticators)
    }

    pub fn verify<T: Serialize + CryptoHash>(&self, message: &T) -> Result<()> {
        let authenticators = self.to_single_key_authenticators()?;
        authenticators
            .iter()
            .try_for_each(|authenticator| authenticator.verify(message))?;
        Ok(())
    }
```

**File:** types/src/transaction/authenticator.rs (L1240-1264)
```rust
impl MultiKey {
    pub fn new(public_keys: Vec<AnyPublicKey>, signatures_required: u8) -> Result<Self> {
        ensure!(
            signatures_required > 0,
            "The number of required signatures is 0."
        );

        ensure!(
            public_keys.len() <= MAX_NUM_OF_SIGS, // This max number of signatures is also the max number of public keys.
            "The number of public keys is greater than {}.",
            MAX_NUM_OF_SIGS
        );

        ensure!(
            public_keys.len() >= signatures_required as usize,
            "The number of public keys is smaller than the number of required signatures, {} < {}",
            public_keys.len(),
            signatures_required
        );

        Ok(Self {
            public_keys,
            signatures_required,
        })
    }
```

**File:** types/src/transaction/authenticator.rs (L1836-1938)
```rust
    #[test]
    fn verify_multi_key_auth() {
        let sender0 = Ed25519PrivateKey::generate_for_testing();
        let sender0_pub = sender0.public_key();
        let any_sender0_pub = AnyPublicKey::ed25519(sender0_pub.clone());
        let sender1 = secp256k1_ecdsa::PrivateKey::generate_for_testing();
        let sender1_pub = sender1.public_key();
        let any_sender1_pub = AnyPublicKey::secp256k1_ecdsa(sender1_pub);

        let keys = vec![
            any_sender0_pub.clone(),
            any_sender1_pub.clone(),
            any_sender1_pub.clone(),
        ];
        let multi_key = MultiKey::new(keys, 2).unwrap();

        let sender_auth = AuthenticationKey::multi_key(multi_key.clone());
        let sender_addr = sender_auth.account_address();

        let raw_txn = crate::test_helpers::transaction_test_helpers::get_test_signed_transaction(
            sender_addr,
            0,
            &sender0,
            sender0_pub,
            None,
            0,
            0,
            None,
        )
        .into_raw_transaction();

        let signature0 = AnySignature::ed25519(sender0.sign(&raw_txn).unwrap());
        let sender0_auth = SingleKeyAuthenticator {
            public_key: any_sender0_pub,
            signature: signature0.clone(),
        };
        let signature1 = AnySignature::secp256k1_ecdsa(sender1.sign(&raw_txn).unwrap());
        let sender1_auth = SingleKeyAuthenticator {
            public_key: any_sender1_pub,
            signature: signature1.clone(),
        };

        let mk_auth_0 =
            MultiKeyAuthenticator::new(multi_key.clone(), vec![(0, signature0.clone())]).unwrap();
        mk_auth_0.to_single_key_authenticators().unwrap_err();
        let account_auth = AccountAuthenticator::multi_key(mk_auth_0);
        let signed_txn = SignedTransaction::new_single_sender(raw_txn.clone(), account_auth);
        signed_txn.verify_signature().unwrap_err();

        let mk_auth_1 =
            MultiKeyAuthenticator::new(multi_key.clone(), vec![(1, signature1.clone())]).unwrap();
        mk_auth_1.to_single_key_authenticators().unwrap_err();
        let account_auth = AccountAuthenticator::multi_key(mk_auth_1);
        let signed_txn = SignedTransaction::new_single_sender(raw_txn.clone(), account_auth);
        signed_txn.verify_signature().unwrap_err();

        let mk_auth_01 = MultiKeyAuthenticator::new(multi_key.clone(), vec![
            (0, signature0.clone()),
            (1, signature1.clone()),
        ])
        .unwrap();
        let single_key_authenticators = mk_auth_01.to_single_key_authenticators().unwrap();
        assert_eq!(single_key_authenticators, vec![
            sender0_auth.clone(),
            sender1_auth.clone()
        ]);
        let account_auth = AccountAuthenticator::multi_key(mk_auth_01);
        let signed_txn = SignedTransaction::new_single_sender(raw_txn.clone(), account_auth);
        signed_txn.verify_signature().unwrap();

        let mk_auth_02 = MultiKeyAuthenticator::new(multi_key.clone(), vec![
            (0, signature0.clone()),
            (2, signature1.clone()),
        ])
        .unwrap();
        let single_key_authenticators = mk_auth_02.to_single_key_authenticators().unwrap();
        assert_eq!(single_key_authenticators, vec![
            sender0_auth.clone(),
            sender1_auth.clone()
        ]);
        let account_auth = AccountAuthenticator::multi_key(mk_auth_02);
        let signed_txn = SignedTransaction::new_single_sender(raw_txn.clone(), account_auth);
        signed_txn.verify_signature().unwrap();

        let mk_auth_12 = MultiKeyAuthenticator::new(multi_key.clone(), vec![
            (1, signature1.clone()),
            (2, signature1.clone()),
        ])
        .unwrap();
        let single_key_authenticators = mk_auth_12.to_single_key_authenticators().unwrap();
        assert_eq!(single_key_authenticators, vec![
            sender1_auth.clone(),
            sender1_auth.clone()
        ]);
        let account_auth = AccountAuthenticator::multi_key(mk_auth_12);
        let signed_txn = SignedTransaction::new_single_sender(raw_txn.clone(), account_auth);
        signed_txn.verify_signature().unwrap();

        MultiKeyAuthenticator::new(multi_key.clone(), vec![
            (0, signature0.clone()),
            (0, signature0.clone()),
        ])
        .unwrap_err();
```

**File:** aptos-move/framework/aptos-framework/sources/multisig_account.move (L1510-1518)
```text
    fun validate_owners(owners: &vector<address>, multisig_account: address) {
        let distinct_owners: vector<address> = vector[];
        owners.for_each_ref(|owner| {
            assert!(owner != &multisig_account, error::invalid_argument(EOWNER_CANNOT_BE_MULTISIG_ACCOUNT_ITSELF));
            let (found, _) = distinct_owners.index_of(owner);
            assert!(!found, error::invalid_argument(EDUPLICATE_OWNER));
            distinct_owners.push_back(*owner);
        });
    }
```

**File:** crates/aptos-crypto/src/multi_ed25519.rs (L511-558)
```rust
    fn verify_arbitrary_msg(
        &self,
        message: &[u8],
        public_key: &MultiEd25519PublicKey,
    ) -> Result<()> {
        // NOTE: Public keys need not be validated because we use ed25519_dalek's verify_strict,
        // which checks for small order public keys.
        match bitmap_last_set_bit(self.bitmap) {
            Some(last_bit) if (last_bit as usize) < public_key.public_keys.len() => (),
            _ => {
                return Err(anyhow!(
                    "{}",
                    CryptoMaterialError::BitVecError("Signature index is out of range".to_string())
                ))
            },
        };
        let num_ones_in_bitmap = bitmap_count_ones(self.bitmap);
        if num_ones_in_bitmap < public_key.threshold as u32 {
            return Err(anyhow!(
                "{}",
                CryptoMaterialError::BitVecError(
                    "Not enough signatures to meet the threshold".to_string()
                )
            ));
        }
        if num_ones_in_bitmap != self.signatures.len() as u32 {
            return Err(anyhow!(
                "{}",
                CryptoMaterialError::BitVecError(
                    "Bitmap ones and signatures count are not equal".to_string()
                )
            ));
        }
        let mut bitmap_index = 0;
        // TODO: Eventually switch to deterministic batch verification
        for sig in &self.signatures {
            while !bitmap_get_bit(self.bitmap, bitmap_index) {
                bitmap_index += 1;
            }
            let pk = public_key
                .public_keys
                .get(bitmap_index)
                .ok_or_else(|| anyhow::anyhow!("Public key index {bitmap_index} out of bounds"))?;
            sig.verify_arbitrary_msg(message, pk)?;
            bitmap_index += 1;
        }
        Ok(())
    }
```
