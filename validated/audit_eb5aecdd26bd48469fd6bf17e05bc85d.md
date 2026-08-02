## Title
`MultiKey` authentication does not enforce distinct public keys, letting a single key holder satisfy a "k‑of‑n" multisig threshold by signing with a duplicated key - (`types/src/transaction/authenticator.rs`)

## Summary
The `MultiKey`/`MultiKeyAuthenticator` scheme (used to derive on-chain `AuthenticationKey`s for k-of-n accounts, analogous in spirit to the excessive-assembly bug's "manual bit/word manipulation without higher-level invariant checks") never checks that the `public_keys` list is free of duplicates. Threshold enforcement is purely a signature-count check against the bitmap, so if the same public key appears more than once in the key list, one private key holder can produce multiple "distinct" signature slots (one per occurrence of their key) and satisfy a threshold that is supposed to represent independent approvers.

## Finding Description
`MultiKey::new` only validates the threshold bounds, not key uniqueness: [1](#0-0) 

`MultiKeyAuthenticator::to_single_key_authenticators`, which is what `AccountAuthenticator::verify`/`TransactionAuthenticator::verify` ultimately rely on, only checks that the number of set bits equals the number of supplied signatures and that this count meets `signatures_required`: [2](#0-1) 

There is no check anywhere in this file (or in `MultiKey::new`) that rejects duplicate entries in `public_keys`. If an account's `AuthenticationKey` is derived from a `MultiKey` containing the same public key at two (or more) indices, an attacker who holds only that one private key can create two "independent" `SingleKeyAuthenticator` entries — one per duplicate index — both carrying valid signatures from the same key, and satisfy a 2-of-n (or higher) threshold alone.

This is demonstrated directly in the existing unit test `verify_multi_key_auth`: a `MultiKey` is built with `keys = [sender0_pub, sender1_pub, sender1_pub]` and `threshold = 2`. Using only `sender1`'s private key, signatures are placed at both index 1 and index 2 (`mk_auth_12`), `to_single_key_authenticators()` succeeds, and `signed_txn.verify_signature()` succeeds — meaning a single signer's key satisfied a nominal 2-of-3 signature requirement: [3](#0-2) 

Because `TransactionAuthenticator::verify` for `SingleSender`/`MultiAgent`/`FeePayer` variants delegates straight into `AccountAuthenticator::verify` → `MultiKeyAuthenticator::verify` without any duplicate-key defense, this same bypass applies at the top-level transaction admission boundary that binds signer material to the sender/fee-payer/secondary-signer set: [4](#0-3) 

## Impact Explanation
Any account (sender, fee payer, or secondary/multi-agent signer) whose authentication key is derived from a `MultiKey` containing a duplicated public key loses its intended k-of-n security guarantee. A single private key holder can unilaterally authorize/execute transactions that were meant to require multiple independent approvers, i.e., unauthorized transaction execution under the wrong (single-party) approval set for what is nominally a multi-party-controlled account. This directly matches the "Authenticator ... accepting the wrong signing material or wrong approval set" admission-gate criterion.

## Likelihood Explanation
Exploitation requires that a `MultiKey` account be configured (at creation or via authentication key rotation) with a repeated public key entry — either through attacker-controlled account setup (e.g., a victim/attacker collaborating to set up an account, or a rotation flow that doesn't screen for duplicates) or through key-rotation logic that doesn't validate uniqueness. Since `MultiKey::new` performs no uniqueness check and the SDK/API path that builds `MultiKeyAuthenticator`/`MultiKey` objects (`api/types/src/transaction.rs`) does not add one either, nothing in the code path prevents this configuration from being created and later exploited.

## Recommendation
In `MultiKey::new`, reject public key lists containing duplicate entries (or, at minimum, cap the "effective" signer count at the number of distinct keys represented in the bitmap when checking against `signatures_required`). Apply the same uniqueness check wherever `MultiKey`/`MultiKeyAuthenticator` objects are constructed from external input (API deserialization, SDK builders, key-rotation entry functions).

## Proof of Concept
The existing test `verify_multi_key_auth` in `types/src/transaction/authenticator.rs` (lines 1837–1904) is itself a working PoC: with `public_keys = [sender0_pub, sender1_pub, sender1_pub]` and `signatures_required = 2`, signing only with `sender1`'s key at bitmap positions 1 and 2 produces a `MultiKeyAuthenticator` that passes `to_single_key_authenticators()` and `signed_txn.verify_signature().unwrap()` succeeds — i.e., one key satisfies a nominal 2-of-3 threshold.

### Citations

**File:** types/src/transaction/authenticator.rs (L821-849)
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
            Self::NoAccountAuthenticator => bail!("No signature to verify."),
            // Abstraction delayed the authentication after prologue.
            Self::Abstract { authenticator } => {
                let original_signing_message = signing_message(message)?;
                ensure!(
                    authenticator.signing_message_digest()
                        == &AASigningData::signing_message_digest(
                            original_signing_message,
                            authenticator.function_info().clone()
                        )?,
                    "The signing message digest provided in Abstract Authenticator is not expected"
                );
                Ok(())
            },
        }
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

**File:** types/src/transaction/authenticator.rs (L1878-1929)
```rust
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
```
