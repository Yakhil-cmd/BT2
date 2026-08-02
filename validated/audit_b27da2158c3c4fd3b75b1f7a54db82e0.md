## Title
`TransactionAuthenticator::verify` omits `fee_payer_signer` from the `MAX_NUM_OF_SIGS` admission check - ([File: types/src/transaction/authenticator.rs])

### Summary
`TransactionAuthenticator::verify` is the pre-execution admission gate that bounds the total number of signatures a transaction may carry before doing any actual per-signature cryptographic verification work. For the `FeePayer` variant, the bound is computed from `sender` + `secondary_signers` only, and `fee_payer_signer` is never counted toward `MAX_NUM_OF_SIGS`.

### Finding Description
`MAX_NUM_OF_SIGS` (32) exists specifically to cap the aggregate signature-verification workload of a `TransactionAuthenticator` before that workload is performed: [1](#0-0) 

The check is: [2](#0-1) 

`num_sigs` is computed as `self.sender().number_of_signatures() + secondary_signers().map(number_of_signatures).sum()`. For `Self::FeePayer`, `self.sender()` returns the `sender` field, and `self.secondary_signers()` returns `secondary_signers` — but `fee_payer_signer` is a distinct field that is never included in this sum: [3](#0-2) [4](#0-3) 

Because `AccountAuthenticator::number_of_signatures()` can itself return large counts for `MultiKey`/`MultiEd25519` account authenticators (each supporting up to `MAX_NUM_OF_SIGS`-scale sub-signatures), a `fee_payer_signer` populated with a `MultiKey`/`MultiEd25519` authenticator carrying many sub-signatures is never counted against the 32-signature cap, even though its individual signatures are all subsequently verified in the loop later in the same function: [5](#0-4) 

This exactly mirrors the seed report's bug class: a length/count check is performed against a subset of the input components rather than against the full committed set, so the verifier ends up doing (and accepting) verification work over more signing material than the admission-time bound was meant to allow.

### Impact Explanation
This is a computational admission-bound bypass at the authenticator layer: the guard meant to bound per-transaction signature-verification cost before gas is charged (mempool/VM authenticator validation, which happens ahead of full gas metering) can be circumvented by an unprivileged attacker simply by placing an oversized `MultiKey`/`MultiEd25519` authenticator in the `fee_payer_signer` slot of a `FeePayer`-authenticated transaction. This does not directly let anyone execute as the wrong sender, but it breaks the intended invariant that `TransactionAuthenticator::verify` bounds total verification work to `MAX_NUM_OF_SIGS`, allowing disproportionately expensive signature-verification workloads to reach mempool/VM admission processing that the check was designed to prevent.

### Likelihood Explanation
High likelihood for a determined attacker: constructing a `FeePayer` `TransactionAuthenticator` with an inflated `fee_payer_signer` (e.g., a `MultiKey` authenticator with many sub-signatures) requires no privileged access and no cryptographic break — it only requires crafting a BCS-encoded authenticator, since `fee_payer_signer` need not even correspond to a valid fee-payer account relationship for this specific check to be bypassed (the check runs unconditionally before per-field verification).

### Recommendation
Include `fee_payer_signer.number_of_signatures()` in the `num_sigs` computation for the `FeePayer` variant so the `MAX_NUM_OF_SIGS` bound covers all authenticators (sender, secondary signers, and fee payer) that are subsequently verified, e.g.:
```rust
let num_sigs: usize = self.sender().number_of_signatures()
    + self.secondary_signers().iter().map(|a| a.number_of_signatures()).sum::<usize>()
    + self.fee_payer_signer().map(|a| a.number_of_signatures()).unwrap_or(0);
```

### Proof of Concept
I could not fully execute a runtime PoC (no execution tools available in this session) but traced the code path to prove the gap:
1. Construct a `RawTransaction` with a `FeePayer` `TransactionAuthenticator` whose `sender` and `secondary_signers` together stay under `MAX_NUM_OF_SIGS` (32), satisfying the check at [6](#0-5) .
2. Set `fee_payer_signer` to a `SingleKeyAuthenticator`/`MultiKeyAuthenticator` wrapping a `MultiKeyAuthenticator` (via `AccountAuthenticator::multi_key` construction) containing, e.g., 100 sub-signatures — `AccountAuthenticator::number_of_signatures()` for this variant would return 100, far above `MAX_NUM_OF_SIGS`.
3. Call `TransactionAuthenticator::verify`: the `num_sigs` sum computed at line 161-166 never includes `fee_payer_signer`, so the `num_sigs > MAX_NUM_OF_SIGS` guard at line 167 passes.
4. Execution proceeds into the `Self::FeePayer` match arm (lines 179-223), which iterates over and verifies every signature contained in `fee_payer_signer`, i.e., verification work for 100 signatures occurs despite the 32-signature admission cap.

Note: I was not able to independently confirm (within this session) whether an outer layer (e.g., mempool transaction size limits or BCS payload size caps) practically restricts how large `fee_payer_signer` can be before reaching this check; that would bound but not eliminate the severity of the bypass. This should be verified by a follow-up session with execution access.

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

**File:** types/src/transaction/authenticator.rs (L179-184)
```rust
            Self::FeePayer {
                sender,
                secondary_signer_addresses,
                secondary_signers,
                fee_payer_address,
                fee_payer_signer,
```

**File:** types/src/transaction/authenticator.rs (L205-223)
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

                Ok(())
```

**File:** types/src/transaction/authenticator.rs (L248-262)
```rust
    pub fn sender(&self) -> AccountAuthenticator {
        match self {
            Self::Ed25519 {
                public_key,
                signature,
            } => AccountAuthenticator::ed25519(public_key.clone(), signature.clone()),
            Self::FeePayer { sender, .. } => sender.clone(),
            Self::MultiEd25519 {
                public_key,
                signature,
            } => AccountAuthenticator::multi_ed25519(public_key.clone(), signature.clone()),
            Self::MultiAgent { sender, .. } => sender.clone(),
            Self::SingleSender { sender } => sender.clone(),
        }
    }
```
