### Title
Missing Duplicate Public Key Check in `MultiKey::new` Allows Single Signer to Satisfy K-of-N Threshold - (File: `types/src/transaction/authenticator.rs`)

### Summary
The native (non-Move) K-of-N transaction authentication scheme, `MultiKey`/`MultiKeyAuthenticator`, does not check that the public keys composing the threshold set are distinct. This mirrors the oracle bug class: a threshold approval scheme that is supposed to require `signatures_required` *independent* signers can be satisfied by a single private key holder if their key is present at more than one index in the key list.

### Finding Description
`MultiKey::new` only validates the threshold bounds and length, never that the entries are unique: [1](#0-0) 

Contrast this with the Move-based multisig account module, which explicitly builds a `distinct_owners` list and aborts on `EDUPLICATE_OWNER`: [2](#0-1) 

and with the crypto-level `MultiEd25519Signature::new`, which explicitly rejects duplicate signature indices via a bitmap check ("Duplicate signature index"): [3](#0-2) 

`MultiKeyAuthenticator` itself only tracks a bitmap of *which indices* signed, and `to_single_key_authenticators`/verification logic maps bitmap-set positions back to `MultiKey.public_keys[index]` without ever checking that those indices resolve to distinct underlying key material: [4](#0-3) 

The existing unit test demonstrates the exact bypass condition: a `MultiKey` is built with `keys = [sender0_pub, sender1_pub, sender1_pub]` (index 1 and index 2 hold the *same* public key) and `signatures_required = 2`: [5](#0-4) 

A `MultiKeyAuthenticator` is then constructed using `sender1`'s single signature placed at both index 1 and index 2: [6](#0-5) 

Because the two signature slots (1 and 2) both map to identical key material, `sender1` alone can produce both "independent" signatures required by the 2-of-3 threshold, entirely bypassing the intent that 2 distinct key holders authorize the transaction.

### Impact Explanation
For any Aptos account whose authentication key is derived from a `MultiKey` (the native, non-Move K-of-N multisig scheme introduced for mixed-key-type accounts, AIP-55-style), if the key list used to construct that account contains a duplicated public key across two or more slots, one private key holder can unilaterally satisfy the `signatures_required` threshold and authorize/execute transactions as that account. This breaks the core security guarantee of the threshold scheme — that `signatures_required` independent parties must cooperate — and can result in a single compromised or malicious participant unilaterally controlling funds/assets/authority that were meant to require multi-party consensus. This is a violation of the "Authenticator ... accepting the wrong approval set" admission invariant.

### Likelihood Explanation
The vulnerable path requires that the account's `MultiKey` public-key list contain a duplicate entry at account-creation/key-rotation time. This can happen either through: (a) a malicious participant in a group key-collection process submitting the same public key under two "distinct member" slots to secretly retain unilateral control while appearing to be one of several equal parties, or (b) tooling/UI bugs that fail to de-duplicate keys before constructing the `MultiKey`. Since the account's authentication key (address) commits to the full key list, an already-deployed honest account with genuinely-distinct keys is unaffected; the risk is concentrated in the account-setup/key-rotation flow, where nothing in `MultiKey::new` prevents the malformed configuration from being accepted as valid.

### Recommendation
Add a uniqueness check for the public keys in `MultiKey::new`, aborting/erroring if any two entries in `public_keys` are equal (analogous to `multisig_account::validate_owners` and `MultiEd25519Signature::new`'s duplicate-index rejection). This should be enforced both in the Rust `MultiKey::new` constructor and in the corresponding API-side `TryFrom<&MultiKeySignature>` conversion path (`api/types/src/transaction.rs`) before a `MultiKeyAuthenticator` is ever constructed.

### Proof of Concept
The existing test `verify_multi_key_auth` already demonstrates the mechanics of the bug (though it does not currently assert on the security implication): [7](#0-6) 
1. Construct `MultiKey::new(vec![pubkeyA, pubkeyB, pubkeyB], 2)` — 2-of-3 threshold, with `pubkeyB` duplicated at index 1 and 2.
2. Derive the account address from this `MultiKey` and fund/own that address as if it required 2 distinct co-signers.
3. Have only the holder of `pubkeyB`'s private key sign the transaction message once, and place that identical signature at both bitmap index 1 and index 2 in `MultiKeyAuthenticator`.
4. `signed_txn.verify_signature()` succeeds, and the transaction executes — despite only one private key ever having been used — bypassing the intended 2-signer threshold.

### Citations

**File:** types/src/transaction/authenticator.rs (L1112-1117)
```rust
#[derive(Clone, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
pub struct MultiKeyAuthenticator {
    public_keys: MultiKey,
    signatures: Vec<AnySignature>,
    signatures_bitmap: aptos_bitvec::BitVec,
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

**File:** aptos-move/framework/aptos-framework/sources/multisig_account.move (L1871-1888)
```text
    #[test(owner_1 = @0x123, owner_2 = @0x124, owner_3 = @0x125)]
    #[expected_failure(abort_code = 0x10001, location = Self)]
    fun test_create_with_duplicate_owners_should_fail(
        owner_1: &signer, owner_2: &signer, owner_3: &signer) {
        setup();
        create_account(address_of(owner_1));
        create_with_owners(
            owner_1,
            vector[
                // Duplicate owner 2 addresses.
                address_of(owner_2),
                address_of(owner_3),
                address_of(owner_2),
            ],
            2,
            vector[],
            vector[]);
    }
```

**File:** crates/aptos-crypto/src/multi_ed25519.rs (L360-383)
```rust
        let mut sorted_signatures = signatures;
        sorted_signatures.sort_by(|a, b| a.1.cmp(&b.1));

        let mut bitmap = [0u8; BITMAP_NUM_OF_BYTES];

        // Check if all indexes are unique and < MAX_NUM_OF_KEYS
        let (sigs, indexes): (Vec<_>, Vec<_>) = sorted_signatures.into_iter().unzip();
        for i in indexes {
            // If an index is out of range.
            if i < MAX_NUM_OF_KEYS as u8 {
                // if an index has been set already (thus, there is a duplicate).
                if bitmap_get_bit(bitmap, i as usize) {
                    return Err(CryptoMaterialError::BitVecError(
                        "Duplicate signature index".to_string(),
                    ));
                } else {
                    bitmap_set_bit(&mut bitmap, i as usize);
                }
            } else {
                return Err(CryptoMaterialError::BitVecError(
                    "Signature index is out of range".to_string(),
                ));
            }
        }
```
