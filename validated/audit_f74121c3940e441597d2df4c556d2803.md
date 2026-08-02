### Title
`MultiKeyAuthenticator`/`MultiKey` accept duplicate public keys, letting a single private key satisfy a k-of-n signature threshold - (File: `types/src/transaction/authenticator.rs`)

### Summary
The `MultiKey` and `MultiKeyAuthenticator` constructors only validate signature/key *count* and *index* uniqueness, never that the underlying **public keys** in the list are distinct. This mirrors the LockManager "remainder" bug class: a value meant to represent independent, non-reusable admission material (a distinct signer) is silently allowed to be reused/duplicated across multiple slots that all count toward the same threshold, letting the admission check ("`signatures_required` signatures") be satisfied with less actual signing material than intended.

### Finding Description
`MultiKey::new` only checks length bounds and that `signatures_required <= public_keys.len()` — it never rejects duplicate entries in `public_keys`: [1](#0-0) 

`MultiKeyAuthenticator::new` deduplicates only by **index** via a bitmap, not by the public key each index refers to: [2](#0-1) 

Verification (`to_single_key_authenticators` + `verify`) simply maps each bitmap-set index to its `AnyPublicKey` slot and independently verifies each `(public_key, signature)` pair; it never asserts that the resolved public keys are pairwise distinct: [3](#0-2) 

The existing unit test in the repo demonstrates this directly: `keys = [any_sender0_pub, any_sender1_pub, any_sender1_pub]` (index 1 and 2 hold the *same* key), with `MultiKey::new(keys, 2)` (2-of-3 threshold). Signing with `(1, signature1)` and `(2, signature1)` — i.e., **the same secp256k1 signature from a single private key `sender1`** placed at both duplicate-key indices — passes full signature verification: [4](#0-3) 

The same lack of duplicate-key validation exists on the API-facing `MultiKeySignature::verify` path used when constructing authenticators from REST/BCS input: [5](#0-4) 

and in the Move-side `multi_key.move` public-key constructor, which likewise never checks for duplicate keys: [6](#0-5) 

Because the authentication key is derived deterministically from the full `MultiKey` byte encoding (`to_authentication_key`), any account whose auth key is set up (at creation or via key rotation) with a public-key list containing duplicates will have its "k distinct signers required" invariant silently broken — the *admission* check (`AccountAuthenticator::verify`) accepts fewer independent signers than the threshold implies.

### Impact Explanation
This breaks the authenticator-level "approval set" binding described in the admission pivots: a k-of-n threshold that is supposed to require k *independent* signing parties can instead be satisfied by 1 party holding a single key that occupies multiple slots in the public-key list. For any downstream system that treats an Aptos MultiKey account's `signatures_required` as a guarantee of distinct-party authorization (e.g., social-recovery wallets, custodial/co-signer setups, DAO-style multi-approval EOAs), this silently downgrades a "2-of-3" or "3-of-5" policy to effectively "1-of-n" whenever a duplicate key is present in the list — a full authorization-strength bypass at the transaction-admission boundary, without any sequence/replay/expiry violation being needed.

### Likelihood Explanation
Medium-to-high: exploitation requires that whoever constructs the `MultiKey` (at account rotation/creation time) includes a duplicated public key — either by mistake, or intentionally by a malicious/compromised co-signer who wants to retain full unilateral control while appearing to be one signer among several in a threshold scheme. Since no on-chain or client-side validation (in Rust `authenticator.rs`, API `transaction.rs`, or Move `multi_key.move`) ever rejects duplicate keys, nothing prevents this setup from being created and later exploited, and the existing test in the repo shows the bypass is fully functional (`signed_txn.verify_signature().unwrap()` succeeds).

### Recommendation
Add duplicate-key validation in all three admission-relevant code paths:
- `MultiKey::new` in `types/src/transaction/authenticator.rs` (Rust authenticator construction).
- `MultiKeySignature::verify` in `api/types/src/transaction.rs` (API input validation).
- `multi_key.move`'s `new_multi_key_from_single_keys` / `deserialize_multi_key` (on-chain Move validation used for auth-key derivation and rotation).
Each should reject public-key lists containing duplicate entries (e.g., via a set/dedup check over the serialized `AnyPublicKey` bytes) before allowing the `MultiKey`/`MultiKeyAuthenticator` to be constructed or accepted as a valid authentication key.

### Proof of Concept
Reproduced directly from the existing repository test (`verify_multi_key_auth`):
1. Build `MultiKey::new(vec![sender0_pub, sender1_pub, sender1_pub], 2)` — a 2-of-3 policy where slots 1 and 2 hold the *same* `sender1` public key.
2. Derive the account's authentication key from this `MultiKey` via `AuthenticationKey::multi_key(...)`.
3. An attacker who only controls `sender1`'s private key signs the raw transaction once, producing `signature1`.
4. Construct `MultiKeyAuthenticator::new(multi_key, vec![(1, signature1.clone()), (2, signature1.clone())])` — reusing the single signature at both duplicate-key indices.
5. `SignedTransaction::new_single_sender(raw_txn, account_auth)` then `signed_txn.verify_signature()` **succeeds**, per [4](#0-3) , despite only one real private key ever having been used — bypassing the intended 2-distinct-signer threshold.

*Uncertainty note*: I was not able to fully trace whether any additional guard exists elsewhere (e.g., in wallet SDKs or account-creation flows outside this repo, or in `account.move`'s key-rotation entry functions) that might reject duplicate keys before an authentication key is committed on-chain; my search of `account.move` and `multisig_account.move` did not surface such a check, but a full audit of all key-rotation entry points was not completed within the available search budget.

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

**File:** types/src/transaction/authenticator.rs (L1201-1207)
```rust
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
