## Finding: Duplicate Public Keys Not Rejected in `MultiKey`/`MultiKeyAuthenticator` Threshold Verification

### Title
MultiKey approval sets accept duplicate public keys, letting one signer's signature satisfy multiple threshold slots and undermine k-of-n distinct-signer guarantees - (File: `types/src/transaction/authenticator.rs`)

### Summary
`MultiKey::new` and the Move-side `multi_key::new_multi_key_from_single_keys` construct a k-of-n public-key list without checking that the `n` public keys are distinct. `MultiKeyAuthenticator::new` only rejects duplicate *signature indices* (bitmap collisions), never duplicate *underlying keys*. Consequently, if a `MultiKey` account is set up (or key-rotated into) with the same public key occupying more than one slot, a single signer holding that one key can supply the same signature at two distinct bitmap indices and satisfy a threshold that is nominally "k distinct approvers."

### Finding Description
- `MultiKey::new` (`types/src/transaction/authenticator.rs:1241-1264`) only validates `signatures_required > 0`, key-count bounds, and `public_keys.len() >= signatures_required`. It performs no uniqueness check on the `public_keys` vector. [1](#0-0) 
- `MultiKeyAuthenticator::new` (`types/src/transaction/authenticator.rs:1120-1151`) tracks a `signatures_bitmap` to reject duplicate *indices*, but never compares the public keys referenced by those indices for equality. [2](#0-1) 
- `to_single_key_authenticators` (`types/src/transaction/authenticator.rs:1167-1199`) and `verify` (`1201-1207`) simply map each bitmap-set index to `public_keys.public_keys[idx]` and independently verify each `(key, signature)` pair, with checks only on bitmap/threshold *counts*, never on distinctness of the keys being satisfied. [3](#0-2) 
- The existing unit test `verify_multi_key_auth` (`types/src/transaction/authenticator.rs:1836-1926`) builds exactly this scenario: `keys = [sender0_pub, sender1_pub, sender1_pub]` with `signatures_required = 2`, then constructs `mk_auth_12` using the *same* `signature1` (from `sender1`) at indices 1 and 2 — i.e., one physical signer's signature satisfying two of the two required threshold slots. `to_single_key_authenticators()` succeeds (no duplicate-key rejection), producing two `SingleKeyAuthenticator`s that both trivially verify (same key, same signature checked twice). [4](#0-3) 
- The same gap exists at the on-chain Move layer: `multi_key::new_multi_key_from_single_keys` (`aptos-move/framework/aptos-stdlib/sources/cryptography/multi_key.move:58-74`) checks key count and threshold bounds only, no uniqueness. [5](#0-4) 
- And at the REST API layer: `MultiKeySignature::verify` (`api/types/src/transaction.rs:2175-2201`) validates counts/thresholds but never checks for duplicate `public_keys` entries. [6](#0-5) 

Because both `AptosVM::validate_transaction` (vm-validator path) and the VM prologue call `transaction.check_signature()` which drives `TransactionAuthenticator::verify` → `AccountAuthenticator::verify` → `MultiKeyAuthenticator::verify`, all three admission layers (REST, vm-validator, VM) converge on the same flawed logic and agree to accept the transaction — there is no divergence to catch this, only a shared blind spot. [7](#0-6) [8](#0-7) 

Note: unrelated to this, `validate_signed_transaction` does check `transaction.contains_duplicate_signers()` (`aptos-move/aptos-vm/src/aptos_vm.rs:1913-1919`), but that check is about duplicate **sender/secondary-signer addresses** in multi-agent/fee-payer transactions, not about duplicate keys within a single `MultiKey` approval set. [9](#0-8) 

### Impact Explanation
A `MultiKey` account's k-of-n threshold is meant to represent k *independent* approving keys. If a key is duplicated in the `public_keys` list (whether by the account creator's design, social-engineering during key-rotation setup, or an oversight), a single signer holding that duplicated key can single-handedly reuse one signature across multiple threshold slots and pass verification without cooperation from the other distinct signers. This breaks the "signer set" / approval-set integrity guarantee explicitly called out as an admission pivot ("multisig approval sets... must bind to the intended account set"). Anyone relying on the public key list to infer "N distinct parties must cooperate" (auditors, co-signers, wallets) can be misled, and control of the account can silently collapse to fewer real approvers than advertised.

### Likelihood Explanation
Constructing such an authenticator requires only unprivileged, client-side control over the transaction's `MultiKeyAuthenticator`/`MultiKey` fields (which are attacker/account-owner supplied BCS data) — no privileged signer or leaked key is needed beyond the one key that is deliberately duplicated. The scenario is directly reproduced by an existing unit test in the codebase, confirming the code path accepts it without any additional gating.

### Recommendation
- Add a uniqueness check on `public_keys` in `MultiKey::new` (Rust) and `multi_key::new_multi_key_from_single_keys` / `deserialize_multi_key` (Move), rejecting duplicate `AnyPublicKey` entries.
- Add the same uniqueness validation to `MultiKeySignature::verify` in the REST API layer (`api/types/src/transaction.rs`).
- Optionally, have `MultiKeyAuthenticator::to_single_key_authenticators`/`verify` defensively reject cases where the set of distinct public keys covered by the signature bitmap is smaller than `signatures_required`.

### Proof of Concept
Using the existing test scaffold in `types/src/transaction/authenticator.rs::verify_multi_key_auth`:
1. Build `MultiKey::new(vec![sender0_pub, sender1_pub, sender1_pub], 2)` — a "2-of-3" account where `sender1_pub` occupies two slots.
2. Sign the raw transaction once with `sender1`'s private key to get `signature1`.
3. Build `MultiKeyAuthenticator::new(multi_key, vec![(1, signature1.clone()), (2, signature1.clone())])` — this succeeds because `MultiKeyAuthenticator::new` only checks bitmap-index duplication, not key duplication.
4. Call `mk_auth_12.to_single_key_authenticators()` — succeeds, yielding two `SingleKeyAuthenticator`s both containing `(sender1_pub, signature1)`.
5. `signed_txn.verify_signature()` (which underlies both vm-validator's `check_signature()` call and VM execution's authenticator verification) succeeds, because each of the two duplicated slots trivially verifies against the same key/signature pair — satisfying the "2 of 3" threshold using only one real signer (`sender1`), with `sender0` never having participated.

This is directly modeled by the code already present at [10](#0-9) , demonstrating the acceptance path exists in the codebase as written.

### Citations

**File:** types/src/transaction/authenticator.rs (L821-833)
```rust
    /// Return Ok if the authenticator's public key matches its signature, Err otherwise
    pub fn verify<T: Serialize + CryptoHash>(&self, message: &T) -> Result<()> {
        match self {
            Self::Ed25519 {
                public_key,
                signature,
            } => signature.verify(message, public_key),
            Self::MultiEd25519 {
                public_key,
                signature,
            } => signature.verify(message, public_key),
            Self::SingleKey { authenticator } => authenticator.verify(message),
            Self::MultiKey { authenticator } => authenticator.verify(message),
```

**File:** types/src/transaction/authenticator.rs (L1120-1151)
```rust
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

**File:** types/src/transaction/authenticator.rs (L1836-1926)
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

**File:** api/types/src/transaction.rs (L2175-2201)
```rust
impl VerifyInput for MultiKeySignature {
    fn verify(&self) -> anyhow::Result<()> {
        if self.public_keys.is_empty() {
            bail!("MultiKey signature has no public keys")
        } else if self.signatures.is_empty() {
            bail!("MultiKey signature has no signatures")
        } else if self.public_keys.len() > MAX_NUM_OF_KEYS {
            bail!(
                "MultiKey signature has over the maximum number of public keys {}",
                MAX_NUM_OF_KEYS
            )
        } else if self.signatures.len() > MAX_NUM_OF_SIGS {
            bail!(
                "MultiKey signature has over the maximum number of signatures {}",
                MAX_NUM_OF_SIGS
            )
        } else if self.signatures.len() != self.signatures_required as usize {
            bail!("MultiKey signature does not the number of signatures required")
        } else if self.signatures_required == 0 {
            bail!("MultiKey signature threshold must be greater than 0")
        } else if self.signatures_required > MAX_NUM_OF_SIGS as u8 {
            bail!("MultiKey signature threshold is greater than the maximum number of signatures")
        }
        let _: AccountAuthenticator = self.try_into()?;
        Ok(())
    }
}
```

**File:** aptos-move/aptos-vm/src/aptos_vm.rs (L1913-1919)
```rust
        // Check transaction format.
        if transaction.contains_duplicate_signers() {
            return Err(VMStatus::error(
                StatusCode::SIGNERS_CONTAIN_DUPLICATES,
                None,
            ));
        }
```

**File:** aptos-move/aptos-vm/src/aptos_vm.rs (L3499-3501)
```rust
        let Ok(txn) = transaction.check_signature() else {
            return VMValidatorResult::error(StatusCode::INVALID_SIGNATURE);
        };
```
