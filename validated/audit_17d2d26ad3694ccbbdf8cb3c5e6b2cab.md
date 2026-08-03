## Title
`MAX_NUM_OF_SIGS` cap check omits `fee_payer_signer`'s signature count in `TransactionAuthenticator::verify` — (File: `types/src/transaction/authenticator.rs`)

### Summary
`TransactionAuthenticator::verify` computes `num_sigs` used against the `MAX_NUM_OF_SIGS` cap by summing `sender().number_of_signatures()` and the count from `self.secondary_signers()`, but for the `FeePayer` variant, `secondary_signers()` deliberately excludes the `fee_payer_signer` field. As a result, the fee payer's own signature-count contribution (which can itself be a nested multi-key authenticator carrying multiple signatures) is never added to `num_sigs`, so the cap check systematically undercounts total signatures whenever a `FeePayer` authenticator is used.

### Finding Description
The cap check is: [1](#0-0) 

`self.secondary_signers()` is defined per variant, and for `FeePayer` it returns only the `secondary_signers` vector — the `fee_payer_signer` is intentionally excluded from this accessor: [2](#0-1) 

Contrast this with `all_signers()`, which correctly appends `fee_payer_signer` on top of `sender()` and `secondary_signers()` when building the full list of authenticators to consider: [3](#0-2) 

Because `verify()` uses `self.secondary_signers()` (not `all_signers()`) for the cap arithmetic, any signature count contributed by `fee_payer_signer.number_of_signatures()` — including a nested multi-key/`SingleKeyAuthenticator` structure with many internal keys — is invisible to the `MAX_NUM_OF_SIGS` check. The actual cryptographic verification loop for `FeePayer` does iterate over `fee_payer_signer` and does verify its signature(s) correctly: [4](#0-3) 

so no forged/unauthenticated signature is accepted — but the accounting invariant "signature count must reflect all cryptographic signatures present" is broken specifically for the fee-payer slot, letting the actual number of signatures verified per transaction exceed the documented/intended `MAX_NUM_OF_SIGS = 32` bound.

### Impact Explanation
`MAX_NUM_OF_SIGS` exists to bound the total signature-verification cost per transaction (comment: "Maximum number of signatures supported in `TransactionAuthenticator`, across all `AccountAuthenticator`s included."). By constructing a `FeePayer` transaction where the `fee_payer_signer` is a nested multi-key authenticator with a large number of internal keys/signatures, an unprivileged attacker (who can freely act as their own sponsor/fee payer) can make the node perform signature verification work beyond the intended 32-signature ceiling while the explicit guard silently reports the transaction as within-cap. This breaks the cap invariant that the codebase relies on to bound per-transaction verification cost, even though it does not by itself let an attacker forge approval from a key they don't control (all included signatures are still individually verified).

### Likelihood Explanation
Any unprivileged account can submit a self-sponsored `FeePayer` transaction and control the structure of its own `fee_payer_signer` field, so triggering the undercount requires no special privileges, leaked keys, or pre-existing approvals — only the ability to build a nested multi-key authenticator and sign with keys the attacker owns.

### Recommendation
Compute `num_sigs` from `self.all_signers()` (or explicitly add `self.fee_payer_signer().map(|s| s.number_of_signatures()).unwrap_or(0)`) instead of `self.secondary_signers()`, so the fee payer's contribution is included in the `MAX_NUM_OF_SIGS` enforcement, matching the accounting already used elsewhere (e.g. `all_signers()`).

### Proof of Concept
1. Construct a `FeePayer` `TransactionAuthenticator` where `sender` and `secondary_signers` together have signature count well under 32 (e.g. count = 1).
2. Set `fee_payer_signer` to a `SingleKeyAuthenticator`/multi-key structure whose `number_of_signatures()` alone is large (e.g. > 31), all signed correctly by keys the attacker controls.
3. Call `TransactionAuthenticator::verify`; observe `num_sigs` computed at lines 161-166 stays under `MAX_NUM_OF_SIGS` (since `fee_payer_signer`'s count is never added), the `if num_sigs > MAX_NUM_OF_SIGS` guard passes, and full verification succeeds — despite the true total signature count across `all_signers()` exceeding 32.
4. Add a unit test asserting `num_sigs` computed via the current formula differs from `self.all_signers().iter().map(|a| a.number_of_signatures()).sum()` when a large `fee_payer_signer` is present, demonstrating the cap-check discrepancy.

### Citations

**File:** types/src/transaction/authenticator.rs (L160-169)
```rust
    pub fn verify(&self, raw_txn: &RawTransaction) -> Result<()> {
        let num_sigs: usize = self.sender().number_of_signatures()
            + self
                .secondary_signers()
                .iter()
                .map(|auth| auth.number_of_signatures())
                .sum::<usize>();
        if num_sigs > MAX_NUM_OF_SIGS {
            return Err(Error::new(AuthenticationError::MaxSignaturesExceeded));
        }
```

**File:** types/src/transaction/authenticator.rs (L206-221)
```rust
                let mut remaining = to_verify
                    .iter()
                    .filter(|verifier| verifier.verify(&no_fee_payer_address_message).is_err())
                    .collect::<Vec<_>>();

                remaining.push(&fee_payer_signer);

                let fee_payer_address_message = RawTransactionWithData::new_fee_payer(
                    raw_txn_for_signing.into_owned(),
                    secondary_signer_addresses.clone(),
                    *fee_payer_address,
                );

                for verifier in remaining {
                    verifier.verify(&fee_payer_address_message)?;
                }
```

**File:** types/src/transaction/authenticator.rs (L282-299)
```rust
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

**File:** types/src/transaction/authenticator.rs (L373-390)
```rust
    pub fn all_signers(&self) -> Vec<AccountAuthenticator> {
        match self {
            // This is to ensure that any new TransactionAuthenticator variant must update this function.
            Self::Ed25519 { .. }
            | Self::MultiEd25519 { .. }
            | Self::MultiAgent { .. }
            | Self::FeePayer { .. }
            | Self::SingleSender { .. } => {
                let mut account_authenticators: Vec<AccountAuthenticator> = vec![];
                account_authenticators.push(self.sender());
                account_authenticators.extend(self.secondary_signers());
                if let Some(fee_payer_signer) = self.fee_payer_signer() {
                    account_authenticators.push(fee_payer_signer);
                }
                account_authenticators
            },
        }
    }
```
