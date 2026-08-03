The vulnerability is confirmed by direct code inspection.

### Title
`TransactionAuthenticator::verify` omits `fee_payer_signer` from the `MAX_NUM_OF_SIGS` signature-count cap - (File: `types/src/transaction/authenticator.rs`)

### Summary
`TransactionAuthenticator::verify` computes the total signature count used to enforce `MAX_NUM_OF_SIGS` by summing only `self.sender().number_of_signatures()` and the `number_of_signatures()` of each entry in `secondary_signers()`. For the `FeePayer` variant, `secondary_signers()` returns only the `secondary_signers` field and never includes `fee_payer_signer`, so `fee_payer_signer.number_of_signatures()` is never counted toward the cap.

### Finding Description
The signature-count guard is: [1](#0-0) 

`secondary_signers()` for `FeePayer` explicitly returns only the `secondary_signers` vector, excluding `fee_payer_signer`: [2](#0-1) 

Because of this, an attacker who controls the `fee_payer_signer` field of a `FeePayer` authenticator (or, in the self-sponsored case, a submitter who controls both sender and fee-payer authenticators) can populate `fee_payer_signer` with a `MultiEd25519`/`MultiKey`-style `AccountAuthenticator` containing an arbitrarily large number of internal signatures, since that authenticator's contribution to `num_sigs` is never added. The cap check at lines 161-169 will pass as long as `sender()` plus `secondary_signers()` stays under 32, regardless of how large `fee_payer_signer`'s internal signature count is.

Actual cryptographic verification of `fee_payer_signer` still happens later in the `FeePayer` match arm (`remaining.push(&fee_payer_signer); ... verifier.verify(&fee_payer_address_message)?;`), so an oversized `fee_payer_signer` cannot forge invalid signatures — it will still need `fee_payer_signer` to actually validate against the raw transaction. However, the invariant that `MAX_NUM_OF_SIGS` bounds total signature-verification work performed per transaction is broken: the fee payer's signer count is unconstrained, which corrupts the intended gas/signature-count admission invariant that this check exists to enforce: [3](#0-2) 

This code path is reached during transaction admission whenever `verify()` is invoked on the transaction's `TransactionAuthenticator`, which happens on the mempool/vm-validator/VM signature-validation path (confirmed by callers in `aptos-move/aptos-vm/src/aptos_vm.rs`, `types/src/transaction/mod.rs`, `vm-validator/src/mocks/mock_vm_validator.rs`, and `api/src/transactions.rs`) — i.e., before/during admission of an unprivileged, attacker-submitted transaction.

### Impact Explanation
The `MAX_NUM_OF_SIGS` cap exists to bound the amount of signature-verification (and associated gas) work a single transaction can force validators/full nodes to perform before rejecting or executing it. By omitting `fee_payer_signer` from the sum, an unprivileged submitter constructing a self-sponsored or third-party-sponsored `FeePayer` transaction (where they also control the `fee_payer_signer`, e.g. self-sponsored gas station patterns, or in test/staging environments where fee-payer key material is attacker-controlled) can attach an oversized multisig authenticator as the fee payer, exceeding the cap the code is supposed to enforce. This corrupts the gas-payer signature-count invariant and admits transactions whose total signature-verification cost is not actually bounded by `MAX_NUM_OF_SIGS`, contrary to the code's stated purpose ("Maximum number of signatures supported in `TransactionAuthenticator`, across all `AccountAuthenticator`s included").

### Likelihood Explanation
High likelihood for any submitter that controls the `fee_payer_signer` (self-sponsored transactions, or setups where the fee payer key is available to the submitter). The `FeePayer` variant and its `fee_payer_signer` field are standard, unprivileged, user-constructible parts of transaction submission — no privileged key or pre-existing approval is required beyond controlling the fee-payer authenticator, which is explicitly allowed by the sponsored-transaction feature.

### Recommendation
Include `fee_payer_signer.number_of_signatures()` in the `num_sigs` computation for the `FeePayer` variant (e.g., by adding it explicitly in `verify()`, or by having `secondary_signers()` account for it, or via a dedicated helper that sums sender + secondary signers + fee payer signer signatures) before comparing against `MAX_NUM_OF_SIGS`.

### Proof of Concept
Construct a `TransactionAuthenticator::FeePayer` where `sender` and `secondary_signers` are minimal (e.g., single Ed25519, totaling well under 32), and `fee_payer_signer` is a `MultiEd25519`/`MultiKey` `AccountAuthenticator` with, e.g., 32+ internal signatures (all validly signing the fee-payer message). Call `verify()`:
- Expected (if cap were correctly enforced): `Err(AuthenticationError::MaxSignaturesExceeded)`.
- Actual (per code at lines 161-169): the pre-check `num_sigs` only reflects `sender()` + `secondary_signers()`, so it stays under 32, the check passes, and `verify()` proceeds to per-signer cryptographic verification and returns `Ok(())` once each signer's signature validates — despite the true total signature count (including the oversized `fee_payer_signer`) exceeding `MAX_NUM_OF_SIGS`. [4](#0-3)

### Citations

**File:** types/src/transaction/authenticator.rs (L32-34)
```rust
/// Maximum number of signatures supported in `TransactionAuthenticator`,
/// across all `AccountAuthenticator`s included.
pub const MAX_NUM_OF_SIGS: usize = 32;
```

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

**File:** types/src/transaction/authenticator.rs (L179-224)
```rust
            Self::FeePayer {
                sender,
                secondary_signer_addresses,
                secondary_signers,
                fee_payer_address,
                fee_payer_signer,
            } => {
                // In the fee payer model, the fee payer address can be optionally signed. We
                // realized when we designed the fee payer model, that we made it too restrictive
                // by requiring the signature over the fee payer address. So now we need to live in
                // a world where we support a multitude of different solutions. The modern approach
                // assumes that some may sign over the address and others will sign over the zero
                // address, so we verify both and only fail if the signature fails for either of
                // them. The legacy approach is to assume the address of the fee payer is signed
                // over.
                let mut to_verify = vec![sender];
                let _ = secondary_signers
                    .iter()
                    .map(|signer| to_verify.push(signer))
                    .collect::<Vec<_>>();

                let no_fee_payer_address_message = RawTransactionWithData::new_fee_payer(
                    raw_txn_for_signing.clone().into_owned(),
                    secondary_signer_addresses.clone(),
                    AccountAddress::ZERO,
                );

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

                Ok(())
            },
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
