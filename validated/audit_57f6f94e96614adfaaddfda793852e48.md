## Title
Length-mismatch between `secondary_signer_addresses` and `secondary_signers` in `TransactionAuthenticator::MultiAgent` is not validated at the authenticator layer, potentially decoupling signer-address binding from actual signature checks - (`File: types/src/transaction/authenticator.rs`)

### Summary
`TransactionAuthenticator::verify` for the `MultiAgent` variant does not assert that `secondary_signer_addresses.len() == secondary_signers.len()` before verifying signatures, unlike the API-layer `MultiAgentSignature::verify` which does perform this check.

### Finding Description
`TransactionAuthenticator::verify` handles `MultiAgent` by building a single signing message from the full `secondary_signer_addresses` list, then only iterating over the `secondary_signers` (authenticator) vector to check each provided signature against that message: [1](#0-0) 

Nowhere in this branch is there a length-equality assertion between `secondary_signer_addresses` and `secondary_signers`. This is in contrast to the higher-level API type `MultiAgentSignature::verify`, which does explicitly bail if lengths mismatch: [2](#0-1) 

Downstream, `TransactionMetadata::new` independently derives `secondary_signers` (the address list used to build `senders()`, i.e., the accounts passed as Move `signer`s) from `secondary_signer_addresses()`, and `secondary_authentication_proofs` from `secondary_signers()` (the authenticator list) — two vectors that are populated from different underlying fields: [3](#0-2) [4](#0-3) 

If these two vectors can have different lengths, `senders()` (sender + secondary addresses) and `authentication_proofs()` (sender proof + secondary proofs) become vectors of different lengths, which is a structurally unsound binding between "authenticated identity" and "address granted signer status."

**However**, I was not able to fully confirm, within the remaining budget, that this actually manifests as an exploitable bypass, because:
1. The path type used at the SDK entrypoint (`SignedTransaction::new_multi_agent` / `sign_multi_agent`) already enforces `secondary_private_keys.len() == secondary_signers.len()` before construction: [5](#0-4) , so a mismatched authenticator can only arise from raw/malicious BCS deserialization of a `TransactionAuthenticator::MultiAgent`, not from the honest SDK path.
2. I could not verify, given tool-call limits, how or whether `TransactionMetadata::senders()` is zipped against `authentication_proofs()` in the actual prologue/VM code (`aptos-move/aptos-vm/src/transaction_validation.rs`, `aptos_vm.rs`) to confirm whether a length mismatch there causes silent truncation (Rust `zip` semantics) that would let an unauthenticated address slip into the effective signer set without any signature check, or whether some other length check exists earlier in this path that I did not locate in this session.

### Impact Explanation
If confirmed, this could allow constructing a MultiAgent transaction where `secondary_signer_addresses` contains an extra, unauthenticated address beyond what `secondary_signers` actually signs for. If the VM prologue accepts this and treats the extra address as an authorized secondary signer (e.g., via `senders()`/Move `signer` binding) without a corresponding valid signature, that would satisfy the exploit's core impact criterion: an authenticator accepting the wrong signing material / wrong signer set. This is not yet proven — it depends on code I could not inspect this session (the actual prologue validation loop that consumes `TransactionMetadata::senders()` and `authentication_proofs()`).

### Likelihood Explanation
Low-to-uncertain. The BCS-level `TransactionAuthenticator::MultiAgent` struct permits constructing mismatched vectors (nothing in `types/src/transaction/authenticator.rs`'s `verify` rejects it), so an attacker who crafts a raw signed transaction (bypassing the SDK helper) could submit one. Whether the VM's downstream consumption of `senders()` / `authentication_proofs()` actually mis-binds addresses to signatures (versus safely rejecting via a length check elsewhere, e.g. in the Move prologue) is unconfirmed.

### Recommendation
Add an explicit length-equality check for `secondary_signer_addresses.len() == secondary_signers.len()` inside `TransactionAuthenticator::verify`'s `MultiAgent` (and `FeePayer`) match arms in `types/src/transaction/authenticator.rs`, mirroring the check already present in `api/types/src/transaction.rs::MultiAgentSignature::verify`, so that a malformed/mismatched authenticator is rejected at signature-verification time regardless of downstream VM logic.

### Proof of Concept
Not fully constructed/validated in this session due to tool-call limits. A concrete PoC would need to:
1. Manually construct (via raw struct construction, not the SDK `sign_multi_agent` helper) a `TransactionAuthenticator::MultiAgent` with `secondary_signer_addresses = [addr_a, addr_b]` but `secondary_signers = [auth_a]` only (one fewer authenticator than addresses).
2. Call `SignedTransaction::verify_signature()` (or the equivalent) and confirm whether it accepts or rejects.
3. If accepted, trace through `TransactionMetadata::new` → prologue validation to see whether `addr_b` is treated as an authorized secondary signer despite no signature being checked for it.

Given the incomplete verification of step 3 against the actual VM prologue code, I cannot assert with confidence that this is a confirmed, exploitable admission-boundary bypass as defined by the review's Decision Standard. It should be treated as a **plausible but unconfirmed** finding — recommend a follow-up Devin session with full read access to `aptos-move/aptos-vm/src/transaction_validation.rs` and `transaction_validation_versioned.rs` to trace the exact prologue signer-binding logic before treating this as validated.

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

**File:** api/types/src/transaction.rs (L2416-2426)
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
```

**File:** aptos-move/aptos-vm/src/transaction_metadata.rs (L132-146)
```rust
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

**File:** types/src/transaction/mod.rs (L471-475)
```rust
        if secondary_private_keys.len() != secondary_signers.len() {
            return Err(format_err!(
                "number of secondary private keys and number of secondary signers don't match"
            ));
        }
```
