## Valid Finding

The code confirms exactly the asymmetry described in the question.

### Title
`TransactionAuthenticator::verify()` MultiAgent branch ignores `secondary_signer_addresses`/`secondary_signers` length mismatch, while `all_signer_auth_keys()` enforces it — ([File: types/src/transaction/authenticator.rs])

### Summary
`TransactionAuthenticator::MultiAgent`'s `verify()` builds the signed message from the full `secondary_signer_addresses` list but only iterates and checks signatures for the entries actually present in `secondary_signers`, with no length-parity check between the two vectors. A sibling function, `all_signer_auth_keys()`, explicitly guards against this same mismatch by returning `None`. This means the two admission-relevant code paths disagree on whether a MultiAgent authenticator with more declared secondary-signer addresses than actual secondary-signer authenticators is acceptable.

### Finding Description
In `TransactionAuthenticator::verify()`: [1](#0-0) 
the `MultiAgent` arm constructs the signing message via `RawTransactionWithData::new_multi_agent(...)` using the *full* `secondary_signer_addresses` vector, then does:
```rust
sender.verify(&message)?;
for signer in secondary_signers {
    signer.verify(&message)?;
}
```
It never asserts `secondary_signer_addresses.len() == secondary_signers.len()`. If `secondary_signer_addresses` has 2 entries but `secondary_signers` has only 1 `AccountAuthenticator`, the loop only verifies that one authenticator's signature over the (2-address) message; the second declared address is never bound to any verified signature. As long as the sender and the single present secondary authenticator verify correctly, `verify()` returns `Ok(())`.

By contrast, `all_signer_auth_keys()`: [2](#0-1) 
explicitly checks `secondary_addresses.len() != secondary_auths.len()` and returns `None` on mismatch — rejecting the exact same malformed authenticator that `verify()` would accept.

`secondary_signer_addresses()` and `secondary_signers()` are plain accessors that just return the two vectors verbatim from the `MultiAgent`/`FeePayer` variant with no cross-validation: [3](#0-2) 

This is a genuine admission-boundary disagreement between two separate validation surfaces built on the same `TransactionAuthenticator` type: the encrypted-transaction/auth-key-binding path (`all_signer_auth_keys`) rejects the malformed authenticator, while the primary signature-verification path (`verify`), which is what mempool/vm-validator/VM actually rely on to admit and execute the transaction, accepts it.

### Impact Explanation
A `MultiAgent` (or `FeePayer`, which shares the same unguarded pattern for `secondary_signer_addresses`/`secondary_signers`) transaction can be constructed where a declared secondary-signer address has no corresponding verified authenticator, yet `verify()` still succeeds. Since `secondary_signer_addresses()` (not `secondary_signers()`) is what is exposed as the "list of secondary signer accounts" for a `SignedTransaction`/`TransactionAuthenticator` and is what downstream consumers (e.g., VM signer construction for multi-agent entry functions) rely on to determine which accounts participate as signers, an address can end up recorded/treated as an approving secondary signer of the transaction without ever having produced a valid signature for it. This breaks the intended guarantee that every account appearing in `secondary_signer_addresses` has cryptographically approved the transaction — a signer-binding violation at the authenticator level.

### Likelihood Explanation
The mismatched structure is trivially constructible client-side (BCS-serialize a `TransactionAuthenticator::MultiAgent` with 2 addresses and 1 authenticator) and requires no privileged keys — only a valid signature from the sender and from the one secondary authenticator that is actually included. The relevant `verify()` code path performs no length check, so nothing in `TransactionAuthenticator::verify()` itself blocks this input from passing signature verification.

### Recommendation
Add an explicit length-parity check in the `MultiAgent` and `FeePayer` arms of `TransactionAuthenticator::verify()` (mirroring the check already present in `all_signer_auth_keys()`), rejecting the authenticator if `secondary_signer_addresses.len() != secondary_signers.len()` before iterating.

### Proof of Concept
1. Construct `RawTransaction` and sign it as sender + one secondary signer over `RawTransactionWithData::new_multi_agent(raw_txn, secondary_signer_addresses)` where `secondary_signer_addresses` contains 2 addresses.
2. Build `TransactionAuthenticator::MultiAgent { sender, secondary_signer_addresses: vec![addr_a, addr_b], secondary_signers: vec![auth_a] }` (only 1 authenticator for 2 addresses).
3. Call `all_signer_auth_keys(sender_address)` → returns `None` (rejected) per lines 349-353.
4. Call `authenticator.verify(&raw_txn)` → iterates only `secondary_signers` (length 1), verifies `sender` and `auth_a`, and returns `Ok(())` despite `addr_b` never producing any authenticator/signature — demonstrating the divergent admission decisions between the two functions. [4](#0-3)

### Citations

**File:** types/src/transaction/authenticator.rs (L229-243)
```rust
            Self::MultiAgent {
                sender,
                secondary_signer_addresses,
                secondary_signers,
            } => {
                let message = RawTransactionWithData::new_multi_agent(
                    raw_txn_for_signing.into_owned(),
                    secondary_signer_addresses.clone(),
                );
                sender.verify(&message)?;
                for signer in secondary_signers {
                    signer.verify(&message)?;
                }
                Ok(())
            },
```

**File:** types/src/transaction/authenticator.rs (L264-299)
```rust
    pub fn secondary_signer_addresses(&self) -> Vec<AccountAddress> {
        match self {
            Self::Ed25519 { .. } | Self::MultiEd25519 { .. } | Self::SingleSender { .. } => {
                vec![]
            },
            Self::FeePayer {
                sender: _,
                secondary_signer_addresses,
                ..
            } => secondary_signer_addresses.to_vec(),
            Self::MultiAgent {
                sender: _,
                secondary_signer_addresses,
                ..
            } => secondary_signer_addresses.to_vec(),
        }
    }

    pub fn secondary_signers(&self) -> Vec<AccountAuthenticator> {
        match self {
            Self::Ed25519 { .. } | Self::MultiEd25519 { .. } | Self::SingleSender { .. } => {
                vec![]
            },
            Self::FeePayer {
                sender: _,
                secondary_signer_addresses: _,
                secondary_signers,
                ..
            } => secondary_signers.to_vec(),
            Self::MultiAgent {
                sender: _,
                secondary_signer_addresses: _,
                secondary_signers,
            } => secondary_signers.to_vec(),
        }
    }
```

**File:** types/src/transaction/authenticator.rs (L333-371)
```rust
    /// Collect `(address, auth_key)` pairs for every signer in the transaction,
    /// in deterministic order: sender, then secondary signers, then fee payer.
    /// Returns `None` if any signer uses an authenticator incompatible with
    /// encrypted transactions (keyless, abstract auth, etc.).
    pub fn all_signer_auth_keys(
        &self,
        sender_address: AccountAddress,
    ) -> Option<Vec<(AccountAddress, AuthenticationKey)>> {
        let mut result = Vec::new();

        let sender_auth = self.sender();
        if !sender_auth.supports_encrypted_txn() {
            return None;
        }
        result.push((sender_address, sender_auth.authentication_key()?));

        let secondary_addresses = self.secondary_signer_addresses();
        let secondary_auths = self.secondary_signers();
        if secondary_addresses.len() != secondary_auths.len() {
            return None;
        }
        for (addr, auth) in secondary_addresses.into_iter().zip(secondary_auths.iter()) {
            if !auth.supports_encrypted_txn() {
                return None;
            }
            result.push((addr, auth.authentication_key()?));
        }

        if let (Some(fee_payer_addr), Some(fee_payer_auth)) =
            (self.fee_payer_address(), self.fee_payer_signer())
        {
            if !fee_payer_auth.supports_encrypted_txn() {
                return None;
            }
            result.push((fee_payer_addr, fee_payer_auth.authentication_key()?));
        }

        Some(result)
    }
```
