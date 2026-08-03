## Finding: Length mismatch between `secondary_signer_addresses` and `secondary_signers` is not enforced in `TransactionAuthenticator::MultiAgent::verify`

### Summary

`TransactionAuthenticator::MultiAgent::verify()` in `types/src/transaction/authenticator.rs` never checks that `secondary_signer_addresses.len() == secondary_signers.len()`. It builds a single signing message from the *entire* `secondary_signer_addresses` list and then only loops over whatever `secondary_signers` authenticators happen to be present, verifying each against that message. If fewer authenticators are supplied than addresses, the extra address(es) are silently accepted with zero signature verification. This is in stark contrast to the equivalent API-layer type, `MultiAgentSignature::verify()` in `api/types/src/transaction.rs`, which explicitly `bail!`s on a length mismatch — showing the core (BCS) path is missing a check that the API layer author clearly considered necessary.

### Finding Description

Core verification code: [1](#0-0) 

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

There is no assertion that `secondary_signer_addresses.len() == secondary_signers.len()`. The loop simply iterates over whatever `secondary_signers` are present — it does not "zip" the two vectors together (so it's not even a lenient-zip truncation bug, it's a complete absence of any cardinality check). If the attacker submits 2 addresses but only 1 authenticator, `verify()` returns `Ok(())` as long as that single authenticator's signature is valid over the message (which does embed both addresses, so the message signed matches, but nothing ever proves the second address's owner authorized anything).

By contrast, the API-side struct used for JSON-format submissions explicitly guards against this: [2](#0-1) 

This asymmetry demonstrates the check was known to be necessary but is absent from the canonical BCS-verified `TransactionAuthenticator` used by mempool/VM validation for all raw-BCS-submitted transactions (the dominant path, e.g. via `/transactions` BCS endpoint or direct mempool ingestion).

Downstream, the unguarded `secondary_signer_addresses` list (not the verified authenticator count) is what propagates into transaction metadata and the Move execution context: [3](#0-2) 

Here, `secondary_signers` (the address list, length 2 in the PoC) and `secondary_authentication_proofs` (derived from the actual authenticators, length 1) diverge in length. `TransactionMetadata::senders()` and `TransactionMetadata::authentication_proofs()` therefore return mismatched-length vectors: [4](#0-3) 

Any downstream consumer that pairs `senders()` with `authentication_proofs()` positionally (e.g. by zip, or by index) will either misalign address-to-proof pairs or silently drop the unauthenticated trailing address from key verification while still treating it as an authenticated secondary signer for account-binding purposes (`is_multi_agent()`, `as_user_transaction_context()` secondary signer list, and ultimately the `signer` capabilities passed into the executed Move entry function).

### Impact Explanation

An unprivileged attacker can craft a BCS `SignedTransaction` whose `TransactionAuthenticator::MultiAgent` has more `secondary_signer_addresses` than `secondary_signers` authenticators. `TransactionAuthenticator::verify()` — the canonical signature-check gate used by mempool/VM validation for BCS-submitted transactions — accepts this without complaint, because it contains no length-equality check at all (unlike the API JSON-path equivalent). This breaks the "secondary signer set must bind to intended, individually-authenticated accounts" guarantee: an address can be pulled into the transaction's `secondary_signers`/signer set metadata without any account owner ever having produced a valid signature for it, which can distort downstream signer-set-dependent logic (account binding for multi-agent scripts, `UserTransactionContext`, replay/approval semantics for anything keyed on the secondary-signer address list).

### Likelihood Explanation

High — this only requires constructing and BCS-serializing a `TransactionAuthenticator::MultiAgent` with mismatched vector lengths, something any unprivileged party can do without needing any privileged key material; the vectors are attacker-controlled at serialization time and `verify()` performs no cardinality check before iterating.

### Recommendation

Add an explicit length check at the top of the `MultiAgent` (and `FeePayer`, which has the identical pattern) arm of `TransactionAuthenticator::verify()`:
```rust
if secondary_signer_addresses.len() != secondary_signers.len() {
    return Err(Error::new(AuthenticationError::...)); // new explicit error variant
}
```
This mirrors the check already present in `api/types/src/transaction.rs`'s `MultiAgentSignature::verify()` and should be added before the signature-verification loop so a mismatched vector length is rejected uniformly regardless of submission path (BCS or JSON).

### Proof of Concept

1. Build a `RawTransaction` for any sender.
2. Construct `TransactionAuthenticator::MultiAgent { sender, secondary_signer_addresses: vec![addr0, addr1], secondary_signers: vec![auth0] }` where `auth0` is a real, valid `AccountAuthenticator` for `addr0` signed over the multi-agent message (built via `RawTransactionWithData::new_multi_agent` with both addresses embedded), and `addr1` is any arbitrary address with no corresponding authenticator supplied.
3. Call `authenticator.verify(&raw_txn)` — per [1](#0-0)  this returns `Ok(())` because the loop only iterates the single provided `secondary_signers` entry; no error is raised for the length mismatch.
4. Compare with `MultiAgentSignature::verify()` at [5](#0-4) , which would `bail!("MultiAgent signatures don't match addresses length")` for the same input shape — confirming the core BCS path lacks a check that the API layer considers mandatory.

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

**File:** api/types/src/transaction.rs (L2416-2432)
```rust
impl VerifyInput for MultiAgentSignature {
    fn verify(&self) -> anyhow::Result<()> {
        self.sender.verify()?;

        if self.secondary_signer_addresses.is_empty() {
            bail!("MultiAgent signature has no secondary signer addresses")
        } else if self.secondary_signers.is_empty() {
            bail!("MultiAgent signature has no secondary signatures")
        } else if self.secondary_signers.len() != self.secondary_signer_addresses.len() {
            bail!("MultiAgent signatures don't match addresses length")
        }

        for signer in self.secondary_signers.iter() {
            signer.verify()?;
        }
        Ok(())
    }
```

**File:** aptos-move/aptos-vm/src/transaction_metadata.rs (L131-146)
```rust
        Ok(Self {
            sender: txn.sender(),
            authentication_proof: txn.authenticator().sender().authentication_proof(),
            secondary_signers: txn.authenticator().secondary_signer_addresses(),
            secondary_authentication_proofs: txn
                .authenticator()
                .secondary_signers()
                .iter()
                .map(|account_auth| account_auth.authentication_proof())
                .collect(),
            replay_protector: txn.replay_protector(),
            fee_payer: txn.authenticator_ref().fee_payer_address(),
            fee_payer_authentication_proof: txn
                .authenticator()
                .fee_payer_signer()
                .map(|signer| signer.authentication_proof()),
```

**File:** aptos-move/aptos-vm/src/transaction_metadata.rs (L248-258)
```rust
    pub fn senders(&self) -> Vec<AccountAddress> {
        let mut senders = vec![self.sender()];
        senders.extend(self.secondary_signers());
        senders
    }

    pub fn authentication_proofs(&self) -> Vec<&AuthenticationProof> {
        let mut proofs = vec![self.authentication_proof()];
        proofs.extend(self.secondary_authentication_proofs.iter());
        proofs
    }
```
