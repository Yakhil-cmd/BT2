## Finding: MultiKey k-of-n authenticator threshold is bypassable via duplicate public keys

### Title
MultiKey / MultiKeyAuthenticator accepts a single private key to satisfy a k-of-n threshold when duplicate public keys are present in the key set - (File: `types/src/transaction/authenticator.rs`)

### Summary
The `MultiKey` public key type and its associated `MultiKeyAuthenticator` verification logic never check that the `public_keys` vector contains distinct keys. Because the on-chain address/authentication key is only a deterministic hash of the (possibly duplicated) key list plus the threshold, an account owner can construct — or rotate into — a "k-of-n" `MultiKey` account where the same underlying key appears at multiple indices. A single holder of that one key can then satisfy the full `signatures_required` threshold alone by reusing one signature at each of the indices that reference the duplicated key, even though the account is presented (by address/threshold metadata) as requiring `k` independent approvers.

### Finding Description
`MultiKey::new` in `types/src/transaction/authenticator.rs` only validates the threshold bounds, never key uniqueness: [1](#0-0) 

The Move-side constructor `new_multi_key_from_single_keys` in `aptos-move/framework/aptos-stdlib/sources/cryptography/multi_key.move` has the identical gap — it only checks `num_keys > 0`, `num_keys <= MAX_NUMBER_OF_PUBLIC_KEYS`, and `signatures_required <= num_keys`: [2](#0-1) 

`MultiKeyAuthenticator::new` (and its `verify`/`to_single_key_authenticators` helpers) only guard against duplicate *signature indices*, not duplicate *public keys* backing those indices: [3](#0-2) [4](#0-3) 

The existing unit test `verify_multi_key_auth` demonstrates the exact bypass: the key set `[any_sender0_pub, any_sender1_pub, any_sender1_pub]` (index 1 and 2 are the same key) with `signatures_required = 2` is accepted as a valid `MultiKey`, and a submission using `signature1` (from the single `sender1` private key) at *both* index 1 and index 2 passes `verify_signature()`: [5](#0-4) 

Because `verify()` iterates the reconstructed `SingleKeyAuthenticator` list and independently checks each `(index, signature)` pair against `public_keys[index]` without any distinctness requirement across indices, a duplicated key satisfies the threshold with a single real signer.

### Impact Explanation
Any account (or `SingleSender`/`SingleKey`-style authenticator) using `MultiKey` as its authentication scheme can be constructed, or an existing single-key account can rotate its authentication key, to a `MultiKey` scheme that outwardly claims a "k-of-n" governance/approval structure (e.g., "requires 3 distinct co-signer approvals") while actually requiring only 1 real private key, because that key is listed multiple times among the `n` public keys. This breaks the "wrong approval set" invariant at the admission boundary: transaction admission logic (`AccountAuthenticator`/`TransactionAuthenticator::verify`, and the analogous Move `multi_key` module used to derive/validate the authentication key) will treat the transaction as properly authorized by `k` independent signers when in fact only one signer key is involved. Any system, custody flow, or on-chain policy that relies on the declared `signatures_required` count as a proxy for the number of independent approvers is undermined — a single key holder can unilaterally satisfy quorum requirements that were meant to require multiple independent signers.

### Likelihood Explanation
The account/key owner fully controls the `public_keys` vector supplied to `MultiKey::new` / `new_multi_key_from_single_keys` at account-creation or authentication-key-rotation time — no privileged action or additional bug is required to insert duplicate keys. Any code path that accepts a caller-supplied `MultiKey` (account creation, `rotate_authentication_key`, or SDK-side signature construction) is affected, and the existing test suite already proves the verification path accepts the duplicated-key, single-signer transaction.

### Recommendation
Enforce distinctness of public keys when constructing a `MultiKey`:
- In `types/src/transaction/authenticator.rs`, `MultiKey::new` should reject vectors containing duplicate `AnyPublicKey` entries (bytewise/serialized equality).
- In `aptos-move/framework/aptos-stdlib/sources/cryptography/multi_key.move`, `new_multi_key_from_single_keys` (and `deserialize_multi_key`, used when parsing a `MultiKey` from bytes at authentication-key-derivation/verification time) should perform the same uniqueness check so that duplicate-key `MultiKey` values can never be constructed or validated on-chain.

### Proof of Concept
The repository's own test demonstrates the bypass end-to-end: [6](#0-5) [5](#0-4) 

1. Construct `MultiKey { public_keys: [pk_A, pk_B, pk_B], signatures_required: 2 }` — accepted by `MultiKey::new`/`new_multi_key_from_single_keys` with no duplicate check.
2. Derive the account's authentication key/address from this `MultiKey` (`to_authentication_key`).
3. As the holder of only `sk_B` (the key behind `pk_B`), sign the transaction once and submit a `MultiKeyAuthenticator` with `(1, sig_B), (2, sig_B)`.
4. `MultiKeyAuthenticator::to_single_key_authenticators` + `verify` accept this as meeting the "2 of 3" threshold, and `SignedTransaction::verify_signature`/`check_signature` (used both in mempool/API admission and VM prologue authentication-key checks) succeed — despite only one real private key participating.

### Citations

**File:** types/src/transaction/authenticator.rs (L1119-1151)
```rust
impl MultiKeyAuthenticator {
    pub fn new(public_keys: MultiKey, signatures: Vec<(u8, AnySignature)>) -> Result<Self> {
        ensure!(
            public_keys.len() < (u8::MAX as usize),
            "Too many public keys, {}, in MultiKeyAuthenticator.",
            public_keys.len(),
        );

        let mut signatures_bitmap = aptos_bitvec::BitVec::with_num_bits(public_keys.len() as u16);
        let mut any_signatures = vec![];

        for (idx, signature) in signatures {
            ensure!(
                (idx as usize) < public_keys.len(),
                "Signature index is out of public key range, {} < {}.",
                idx,
                public_keys.len(),
            );
            ensure!(
                !signatures_bitmap.is_set(idx as u16),
                "Duplicate signature index, {}.",
                idx
            );
            signatures_bitmap.set(idx as u16);
            any_signatures.push(signature);
        }

        Ok(MultiKeyAuthenticator {
            public_keys,
            signatures: any_signatures,
            signatures_bitmap,
        })
    }
```

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

**File:** types/src/transaction/authenticator.rs (L1241-1264)
```rust
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

**File:** types/src/transaction/authenticator.rs (L1845-1850)
```rust
        let keys = vec![
            any_sender0_pub.clone(),
            any_sender1_pub.clone(),
            any_sender1_pub.clone(),
        ];
        let multi_key = MultiKey::new(keys, 2).unwrap();
```

**File:** types/src/transaction/authenticator.rs (L1920-1932)
```rust
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
