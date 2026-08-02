## Title
`MultiKey` (K-of-N) authenticator does not reject duplicate public keys, letting a single signer satisfy multiple approval "slots" — ([File: types/src/transaction/authenticator.rs])

### Summary
The Aptos `MultiKey` authenticator (the generic K-of-N multi-signature scheme that replaced/extends `MultiEd25519` and supports mixed key types) does not enforce that the N public keys in the key set are distinct. This lets a `signatures_required = K` account be constructed where fewer than K distinct private-key holders can produce a transaction that is treated as fully "K-of-N approved," because one key occupies more than one index/slot in the key vector and the same signature can be reused (or independently re-signed) across those indices.

### Finding Description
`MultiKey::new` performs no uniqueness check on the supplied public keys: [1](#0-0) 

It only validates that `signatures_required > 0`, that the key count is within `MAX_NUM_OF_SIGS`, and that there are at least `signatures_required` keys — never that the keys are pairwise distinct. The on-chain Move counterpart used to build `MultiKey` public keys, `multi_key::new_multi_key_from_single_keys`, has the identical gap: [2](#0-1) 

The authentication key is simply `sha3_256(bcs(MultiKey) || scheme_id)` [3](#0-2) , so a key set containing duplicate entries hashes to a perfectly valid, distinct account address — there is nothing that prevents such an account from being created or used.

At verification time, each of the K required signatures is checked against the public key at its own index (`MultiKeyAuthenticator` pairs a signature index with the key list) — it does not cross-check that all K satisfied indices map to distinct underlying keys. The project's own unit test demonstrates this directly: a `MultiKey` is built from `[key0, key1, key1]` (key1 duplicated at index 1 and 2), and a `MultiKeyAuthenticator` supplying **the same signature from key1** for **both** index 1 and index 2 passes `verify_signature()` successfully: [4](#0-3) 

This is precisely a 2-of-3 threshold being satisfied by one actual signer (key0's holder is not needed at all, and key1's holder alone supplies both required "signatures").

### Impact Explanation
This breaks the core security invariant of K-of-N multisig authentication: the whole premise of `signatures_required = K` (used for DAO/multisig accounts, treasury accounts, shared custody, etc.) is that K *independent* parties must approve a transaction. If duplicate keys can be included in the key set — whether through a compromised/malicious co-owner submitting duplicate entries during account setup, a UI/SDK bug that fails to dedupe, or a governance process that doesn't explicitly reject repeats — the effective threshold collapses. A single key holder occupying two or more index slots can authorize a transaction that should require true collaboration among multiple signers, i.e., "authenticator ... multisig ... validation accepting the wrong approval set," directly matching the required admission-boundary impact category. This can lead to unauthorized execution of transactions from an account whose owners believed a stronger K-of-N guarantee was in force.

### Likelihood Explanation
The check is missing in both the Rust type layer (`MultiKey::new`) and the on-chain Move constructor (`multi_key::new_multi_key_from_single_keys`), so there is no independent layer that rejects duplicate keys. Exploitation requires that a duplicate-key `MultiKey` account actually gets set up (e.g., via `create_with_owners`/`rotate_authentication_key` flows that accept a `MultiKey` public key, or a governance/DAO tool that lets participants submit their own public key entries without deduplication). This is plausible in any workflow that programmatically assembles multi-key owner lists (e.g., from a list of member addresses/keys) without explicit dedup logic, and is fully exercised and passing in the codebase's own test suite, confirming the behavior is real and unguarded rather than a hypothetical.

### Recommendation
- Add a uniqueness check in `MultiKey::new` (Rust) and `multi_key::new_multi_key_from_single_keys` / `deserialize_multi_key` (Move) that rejects any public-key vector containing duplicate entries.
- Additionally (defense in depth), reject authenticators/threshold checks where two or more satisfied signature indices resolve to the same underlying public key, so that even pre-existing duplicate-key accounts cannot have their effective threshold reduced.

### Proof of Concept
The existing repository test is itself a working PoC: [5](#0-4) [4](#0-3) 

Steps: (1) build `MultiKey::new(vec![key0, key1, key1], 2)` — succeeds with no duplicate check; (2) derive the authentication key/account address from this `MultiKey` (2-of-3 threshold, but only 2 distinct keys, one of which is repeated); (3) have only the holder of `key1` sign the transaction once, and supply that single signature as the authenticator for both index 1 and index 2; (4) `MultiKeyAuthenticator::verify`/`signed_txn.verify_signature()` succeeds, meaning a transaction from this "2-of-3" account was authorized using only 1 distinct signer, with `key0`'s holder never participating.

*Note: I was unable to fully trace, within the available iterations, every on-chain code path that constructs `MultiKey` accounts (e.g., specific multisig/governance module entry points) to confirm which real-world flows would let an attacker or a colluding co-owner actually register a duplicate-key account; this would need further investigation before considering this exploitable end-to-end on a production deployment.*

### Citations

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

**File:** aptos-move/framework/aptos-stdlib/sources/cryptography/multi_key.move (L83-88)
```text
    /// Returns the authentication key for a MultiKey public key.
    public fun to_authentication_key(self: &MultiKey): vector<u8> {
        let pk_bytes = bcs::to_bytes(self);
        pk_bytes.push_back(SIGNATURE_SCHEME_ID);
        hash::sha3_256(pk_bytes)
    }
```
