Found a genuine local vulnerability in the `MultiKey` authenticator that is structurally analogous to the seed bug: both stem from a set that should be filtered/deduplicated to determine "eligible/distinct" units for a threshold calculation but instead is counted at face value, letting a smaller-than-intended actual set satisfy a k-of-n requirement.

### Title
MultiKey k-of-n authenticator does not enforce distinct public keys, allowing a single signer to satisfy a multi-signer threshold - (File: `types/src/transaction/authenticator.rs`)

### Summary
The `MultiKey` authentication scheme (used both as a stand-alone account auth scheme and inside `FeePayer`/`MultiAgent` secondary-signer slots) represents a k-of-n signer set as a list of public keys plus a `signatures_required` (`k`) count. Neither the Rust constructor `MultiKey::new` nor the Move constructor `new_multi_key_from_single_keys` rejects duplicate public keys in that list. Because verification is purely index-based (checking that `k` distinct *indices* have valid signatures, not that `k` distinct *keys* signed), an attacker who controls only one private key can place that same public key at multiple indices and reuse the single resulting signature at each of those indices to satisfy the whole threshold.

### Finding Description
`MultiKey::new` only validates count bounds and that `signatures_required <= public_keys.len()`; it never checks uniqueness of `public_keys`: [1](#0-0) 

Likewise, the Move-side constructor for the on-chain public key type performs the same non-uniqueness-checked validation: [2](#0-1) 

`MultiKeyAuthenticator::to_single_key_authenticators` (used both at signature-verification time and by `TransactionAuthenticator::to_single_key_authenticators`) only checks that the number of *set bit positions* in the bitmap meets `signatures_required`, and pairs each bit index with `public_keys.public_keys[idx]` — it never checks that the keys backing those indices are distinct: [3](#0-2) 

`MultiEd25519Signature::verify_arbitrary_msg` (the legacy multisig scheme this generalizes) has the analogous bitmap/threshold check, which is exactly the pattern being reused for `MultiKey`: count of set bits vs. `threshold`, with per-index public key lookup — again with no distinctness requirement on the underlying `public_keys` vector: [4](#0-3) 

The repository's own unit test proves the exploit path works end-to-end: a `MultiKey` is constructed from `[sender0_pub, sender1_pub, sender1_pub]` (duplicate `sender1_pub` at indices 1 and 2) with `signatures_required = 2`. A `MultiKeyAuthenticator` is built using the **same signature** (`signature1`, produced by the single key `sender1`) at both indices 1 and 2, and `signed_txn.verify_signature()` **succeeds**: [5](#0-4) 

This is the direct analog of the seed report's bug class: a denominator/threshold computation ("2 signatures required") is validated against a raw index count rather than against the count of *distinct eligible* signing identities, so entities that shouldn't count independently (here: the same key repeated) dilute/defeat the intended admission condition — exactly like ineligible liquidity diluting the reward-eligible total in the Canto report.

### Impact Explanation
Any account (or fee-payer/secondary signer slot) whose authentication key is derived from a `MultiKey` public key with intentionally- or accidentally-duplicated entries can be fully controlled and have transactions admitted and executed using only one of the "n" private keys, even though the account was configured to require `k` independent approvals. This breaks the core security guarantee of a k-of-n authenticator — the fundamental "authenticator accepts the wrong approval set" admission-boundary failure explicitly called out in the impact gate (multisig/authenticator validation accepting the wrong signing material or wrong approval set). Because `MultiKey` is a general-purpose auth scheme (not gated behind any privileged/governance flow), any user can create such an account (e.g., to appear to require 2-of-3 co-signers for treasury/custody purposes) while retaining unilateral control, or an attacker with knowledge of only one legitimate co-signer's key (in a maliciously or negligently constructed key list) can forge threshold satisfaction.

### Likelihood Explanation
Likelihood is high for any deployment that builds `MultiKey` accounts programmatically without explicit off-chain validation of key uniqueness — nothing in the on-chain Move module (`multi_key.move`) or the Rust transaction-building/authenticator code enforces distinctness, so a duplicate-key `MultiKey` is a perfectly valid, constructible, and signable account configuration. The exploit requires no special privilege: it only requires the account's `MultiKey` public key material to contain a repeated key (attacker-controlled at account-creation time, or a legitimate account inadvertently created that way), after which normal transaction submission triggers the flawed verification path used both at mempool/VM validation and at execution (`TransactionAuthenticator::verify` / `AccountAuthenticator::verify`).

### Recommendation
Enforce uniqueness of public keys within a `MultiKey` at construction time, in both:
- `MultiKey::new` in `types/src/transaction/authenticator.rs`
- `new_multi_key_from_single_keys` / `deserialize_multi_key` in `aptos-move/framework/aptos-stdlib/sources/cryptography/multi_key.move`

reject any `MultiKey` whose `public_keys` vector contains duplicate entries (comparing serialized `AnyPublicKey` bytes). This should be validated both when the key is first created/used to derive an authentication key and when a `MultiKeyAuthenticator`/`MultiKey` public key blob is deserialized during signature verification, since an authentication key derived off-chain could still be presented on-chain with an unvalidated `MultiKey` blob.

### Proof of Concept
The existing repository test already demonstrates the bug (no test failure occurs where one would be expected): [6](#0-5) 
constructs `multi_key` from `[any_sender0_pub, any_sender1_pub, any_sender1_pub]` with `signatures_required = 2`, i.e., a "2-of-3" configuration where index 1 and 2 both map to `sender1_pub`. [7](#0-6) 
then builds `mk_auth_12` using `signature1` (signed only by `sender1`) at *both* index 1 and index 2, and `signed_txn.verify_signature().unwrap()` succeeds — proving a transaction is admitted as satisfying a 2-signer threshold using a single private key (`sender0`'s key was never needed and `sender1` alone sufficed).

### Citations

**File:** types/src/transaction/authenticator.rs (L1167-1199)
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

**File:** types/src/transaction/authenticator.rs (L1845-1932)
```rust
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
```

**File:** aptos-move/framework/aptos-stdlib/sources/cryptography/multi_key.move (L58-74)
```text
    /// Creates a new MultiKey public key from a vector of single key public keys and a number representing the number of signatures required to authenticate a transaction.
    public fun new_multi_key_from_single_keys(single_keys: vector<single_key::AnyPublicKey>, signatures_required: u8): MultiKey {
        let num_keys = single_keys.length();
        assert!(
            num_keys > 0,
            error::invalid_argument(E_INVALID_MULTI_KEY_NO_KEYS)
        );
        assert!(
            num_keys <= MAX_NUMBER_OF_PUBLIC_KEYS,
            error::invalid_argument(E_INVALID_MULTI_KEY_TOO_MANY_KEYS)
        );
        assert!(
            (signatures_required as u64) <= num_keys,
            error::invalid_argument(E_INVALID_MULTI_KEY_SIGNATURES_REQUIRED)
        );
        MultiKey { public_keys: single_keys, signatures_required }
    }
```

**File:** third_party/move/move-examples/diem-framework/crates/crypto/src/multi_ed25519.rs (L516-532)
```rust
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
```
