## Title
Duplicate public keys within a `MultiKey` allow one real signature to satisfy a k-of-n threshold that should require k distinct signers - (File: `types/src/transaction/authenticator.rs`)

### Summary
Neither the Rust `MultiKeyAuthenticator` verification path nor the Move `multi_key` stdlib module enforce that the public keys inside a `MultiKey` are distinct. Because approval accounting is done purely by **index** (via a bitmap), an attacker who controls (or helps assemble) a `MultiKey` account can place the same public key at two different indices. A single real signature, submitted twice under the two indices, is accepted as two independent approvals, satisfying `signatures_required = 2` (or any k) while only one real private key is used.

### Finding Description
- `MultiKeyAuthenticator::new` only rejects **duplicate signature indices**, not duplicate underlying public keys: [1](#0-0) 
- `to_single_key_authenticators` builds one `SingleKeyAuthenticator` per bitmap index by indexing straight into `public_keys.public_keys[idx]`, with no de-duplication by key content: [2](#0-1) 
- `verify` then simply loops over all expanded single-key authenticators and checks each signature independently, again with no tracking of which *distinct* key already contributed an approval: [3](#0-2) 
- The Move-side constructor used to build/rotate a `MultiKey` public key (e.g. during authentication-key rotation) only validates key count and threshold bounds, never uniqueness of the individual public keys: [4](#0-3) 

Given `public_keys = [pk_A, pk_A]` and `signatures_required = 2`, a holder of the single private key for `pk_A` can sign the transaction once and submit that signature at index 0 and again at index 1. `MultiKeyAuthenticator::new` accepts this (indices 0 and 1 are not duplicates), and `verify` independently validates the same signature against the same key twice, so the authenticator is treated as satisfying a 2-out-of-2 approval when in reality only one distinct signer participated.

### Impact Explanation
This breaks the invariant that `signatures_required` distinct keys are needed to authorize a transaction from a `MultiKey` account. In any scenario where a `MultiKey` is meant to represent a set of *independent* approvers (e.g. co-owned/multi-party accounts, keyless backup-key rotation flows using `multi_key::new_multi_key_from_single_keys`, or externally-agreed k-of-n policies), a party that can register (or trick others into registering) a duplicated key can single-handedly satisfy the threshold, defeating the intended multi-party approval guarantee.

### Likelihood Explanation
This requires the attacker to control the composition of the `MultiKey` set for the account they are signing for (i.e., they must be one of the parties setting up or rotating the account's authentication key to a `MultiKey` with a repeated entry). No privileged signer, leaked key, or pre-existing approval right of another party is needed - the flaw is that the system never enforces distinctness of keys, so nothing prevents an untrusted co-signer from inserting a duplicate of their own key into the set to unilaterally reach the threshold.

### Recommendation
- In `MultiKeyAuthenticator::new` (and/or `MultiKey` construction), reject public-key vectors containing duplicate entries (compare serialized `AnyPublicKey` bytes), not just duplicate signature indices.
- Add the equivalent uniqueness check to `multi_key::new_multi_key_from_single_keys` / `deserialize_multi_key` in the Move stdlib so on-chain rotation/creation of `MultiKey` accounts cannot embed duplicate keys either.

### Proof of Concept
Conceptual Rust test (mirrors existing test patterns in the file, e.g. the duplicate-index test at): [5](#0-4) 

```rust
let key_a = Secp256r1EcdsaPrivateKey::generate_for_testing();
let pk_a = AnyPublicKey::secp256r1_ecdsa(key_a.public_key());

// MultiKey with the SAME public key at index 0 and 1, threshold = 2
let multi_key = MultiKey::new(vec![pk_a.clone(), pk_a.clone()], 2).unwrap();

let sig = AnySignature::secp256r1_ecdsa(key_a.sign(&raw_txn).unwrap());

// One real signature reused at two distinct indices
let mk_auth = MultiKeyAuthenticator::new(multi_key, vec![
    (0, sig.clone()),
    (1, sig.clone()),
]).unwrap(); // succeeds: indices differ, no key-uniqueness check

mk_auth.verify(&raw_txn).unwrap(); // succeeds: 1 real key satisfies "2 of 2"
```

This demonstrates that `signatures_required = 2` is satisfied with only one distinct real signer, contradicting the expected k-distinct-signer guarantee of `MultiKey`/`MultiKeyAuthenticator`.

### Citations

**File:** types/src/transaction/authenticator.rs (L1130-1144)
```rust
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
```

**File:** types/src/transaction/authenticator.rs (L1191-1198)
```rust
        let authenticators: Vec<SingleKeyAuthenticator> =
            std::iter::zip(self.signatures_bitmap.iter_ones(), self.signatures.iter())
                .map(|(idx, sig)| SingleKeyAuthenticator {
                    public_key: self.public_keys.public_keys[idx].clone(),
                    signature: sig.clone(),
                })
                .collect();
        Ok(authenticators)
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

**File:** types/src/transaction/authenticator.rs (L1934-1938)
```rust
        MultiKeyAuthenticator::new(multi_key.clone(), vec![
            (0, signature0.clone()),
            (0, signature0.clone()),
        ])
        .unwrap_err();
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
