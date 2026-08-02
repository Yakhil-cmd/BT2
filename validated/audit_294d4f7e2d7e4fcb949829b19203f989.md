## Title
`MultiKey::new` accepts duplicate public keys, letting a single key holder satisfy a multi-key signature threshold alone - (File: `types/src/transaction/authenticator.rs`)

### Summary
`MultiKey::new` (used to build the account authentication scheme for `SingleKey`/`MultiKey` accounts, AIP-55) only validates the threshold bounds and key count, but never checks that the supplied public keys are distinct. `MultiKeyAuthenticator::new`/`verify_arbitrary_msg` then count *bitmap indices* against `signatures_required`, not distinct keys. If the same public key occupies two indices in `MultiKey.public_keys`, one signature can be reused to fill both index slots, letting the holder of that single key satisfy a threshold that was meant to require multiple independent keys.

### Finding Description
`MultiKey::new` in `types/src/transaction/authenticator.rs` (around lines 1240-1264) performs these checks only: [1](#0-0) 
- `signatures_required > 0`
- `public_keys.len() <= MAX_NUM_OF_SIGS`
- `public_keys.len() >= signatures_required`

There is no `contains`/dedup check on `public_keys`, unlike the analogous `validate_owners` function in `multisig_account.move` which explicitly rejects duplicate owners: [2](#0-1) 

Verification treats the public-key list as index slots. `MultiKeyAuthenticator::new` only rejects duplicate *indices*, not duplicate *keys* at different indices: [3](#0-2) 
And `to_single_key_authenticators`/signature verification iterate over `all_signers()`/bitmap positions and simply verify each signature against `public_keys[index]`, counting `num ones in bitmap >= signatures_required` — it never checks the underlying keys at those indices are distinct.

The existing unit test `verify_multi_key_auth` in the same file demonstrates the exact exploit path: a `MultiKey` is constructed with keys `[sender0_pub, sender1_pub, sender1_pub]` (sender1's key duplicated at indices 1 and 2) and threshold 2: [4](#0-3) 
Then a `MultiKeyAuthenticator` is built using **only sender1's signature**, submitted twice, once for index 1 and once for index 2: [5](#0-4) 
`signed_txn.verify_signature().unwrap()` succeeds — i.e., the 2-of-3 threshold is satisfied using a single distinct private key (sender1's), with `sender0`'s key never involved at all.

This is a structural analog to the "duplicate asset can be added" pattern from the external report: a constructor (`initialize` there, `MultiKey::new` here) is missing a duplicate-entry check, and downstream logic that assumes uniqueness of entries (asset list / signer-threshold accounting) is silently corrupted.

### Impact Explanation
The `MultiKey` authentication scheme (via `AuthenticationKey::multi_key`) determines the on-chain account address and the required approval set for that account (used directly as a sender or fee-payer authenticator, or as members of multi-agent/fee-payer secondary signers). The `signatures_required` (threshold) value is meant to express "N independent approvers must sign." Because `MultiKey::new` does not dedupe, a threshold of N can be met by fewer than N *distinct* keys whenever the key list contains repeats. This breaks the approval-set invariant required by the "Admission Pivots": *"Authenticator, WebAuthn, multisig, or approval validation accepting the wrong signing material or wrong approval set."* Any workflow that constructs a `MultiKey` account/authenticator from externally supplied or merged key lists (e.g., key-rotation flows that append a new key to an existing set, or third-party wallet/custody tooling that builds a `MultiKey` from user-supplied key material) can end up with an account whose "N-of-M" security guarantee silently degrades to fewer independent signers than configured, without any error being raised at construction or verification time.

### Likelihood Explanation
This requires only that a `MultiKey` be constructed with a duplicate public key — no privileged access is needed, since `MultiKey::new`/`MultiKeyAuthenticator::new` are ordinary public constructors invoked by client-side transaction/account building code (also exposed via the REST API path `TryFrom<&MultiKeySignature> for AccountAuthenticator` in `api/types/src/transaction.rs`, which forwards user-supplied public keys straight into `MultiKey::new` without additional validation) [6](#0-5) 
No modification to validated indices or expiry/replay logic is needed; the flaw is purely in the missing uniqueness invariant. Given that the framework already enforces the equivalent invariant for `multisig_account.move` owners (`validate_owners`) but not for `MultiKey` public keys, this is a real gap rather than an intentional design choice.

### Recommendation
Add a uniqueness check for `public_keys` in `MultiKey::new` (and equivalently validate at deserialization/BCS boundaries, since `MultiKey` is also constructed via `TryFrom`/deserialize paths), e.g.:
```rust
let mut seen = std::collections::HashSet::new();
ensure!(
    public_keys.iter().all(|pk| seen.insert(pk.to_bytes())),
    "Duplicate public key in MultiKey."
);
```
This should be enforced both in the Rust constructor and ideally mirrored by an on-chain/Move-side check if `MultiKey` bytes are validated when used to derive authentication keys, consistent with `multisig_account::validate_owners`.

### Proof of Concept
The existing repository test already is a full PoC of the broken invariant (it currently asserts success, which is the bug): [7](#0-6) 
Steps:
1. Build `MultiKey::new(vec![sender0_pub, sender1_pub, sender1_pub], 2)` — succeeds despite `sender1_pub` appearing twice.
2. Derive an account address from this `MultiKey` via `AuthenticationKey::multi_key`.
3. Sign the raw transaction only with `sender1`'s private key, producing one `AnySignature`.
4. Construct `MultiKeyAuthenticator::new(multi_key, vec![(1, signature1.clone()), (2, signature1.clone())])` — succeeds (indices 1 and 2 are distinct bitmap slots even though they map to the same key).
5. Call `signed_txn.verify_signature()` — succeeds, satisfying the threshold-2 requirement using only one distinct private key (`sender0`'s key/signature is never provided).

**Uncertainty / caveats**: I could not fully trace every caller that constructs a `MultiKey` from externally-influenced key lists (e.g., specific wallet/key-rotation flows) within the indexed portion of the codebase, so I cannot confirm every concrete real-world scenario where an attacker-controlled or merged key list would reach `MultiKey::new`; the REST API deserialization path (`api/types/src/transaction.rs`) is the clearest such entry point I verified. Due to index size limits, some files may not be fully covered — a full Devin session could confirm all reachable call sites.

### Citations

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

**File:** types/src/transaction/authenticator.rs (L1837-1932)
```rust
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
```

**File:** types/src/transaction/authenticator.rs (L1934-1939)
```rust
        MultiKeyAuthenticator::new(multi_key.clone(), vec![
            (0, signature0.clone()),
            (0, signature0.clone()),
        ])
        .unwrap_err();
    }
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

**File:** api/types/src/transaction.rs (L2299-2301)
```rust
        let multi_key = MultiKey::new(public_keys, value.signatures_required)?;
        let auth = MultiKeyAuthenticator::new(multi_key, signatures)?;
        Ok(AccountAuthenticator::multi_key(auth))
```
