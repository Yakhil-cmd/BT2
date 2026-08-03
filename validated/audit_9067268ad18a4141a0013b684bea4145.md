No vulnerability found for this question.

**Analysis:**

1. **Not an unprivileged admission path.** `process_chunky_dkg_result_inner` in [1](#0-0)  processes a `CertifiedChunkyDKGOutput` carried inside a `ValidatorTransaction::ChunkyDKGResult` [2](#0-1) . This transaction type is produced by the validator's own `dkg_manager` after collecting a quorum-certified aggregate signature and pushed into the `vtxn_pool` for consensus proposal [3](#0-2) , then included in blocks by the consensus leader — not submitted by ordinary users through mempool/API/authenticator paths. The review boundary explicitly requires the path to "start from unprivileged transaction, authenticator, API, or proof input" and to "ignore peer-driven scenarios" — validator transactions are a peer/validator-driven consensus artifact, out of scope.

2. **Even ignoring scope, the described exploit is already blocked by existing checks.** The `metadata.epoch` vs `config_resource.epoch()` check (line 115) and the `trx.dealer_epoch` vs `metadata.epoch` check (line 149) are sequenced *before* signature verification (lines 152-154) [4](#0-3) . If an attacker forges `metadata.epoch` to equal the current config epoch while the signed `transcript_bytes`'s `dealer_epoch` differs, the check at line 149 rejects the transaction with `EpochNotCurrent` before any signature check occurs — exactly the scenario the question's "proof idea" describes, and it is exactly the mitigation already in place. To make `trx.dealer_epoch == metadata.epoch` pass, the attacker would need `transcript_bytes` to actually contain the forged epoch, but then `verify_multi_signatures(&trx, &signature)` (line 152) would fail unless the attacker also holds a valid quorum aggregate signature over that content — which requires validator signing keys, a privileged capability explicitly excluded by the review's decision standard ("Reject anything that needs a privileged signer, leaked key, or pre-existing approval right").

No exploitable epoch-gate bypass exists at this admission boundary.

### Citations

**File:** aptos-move/aptos-vm/src/validator_txns/chunky_dkg.rs (L90-97)
```rust
    fn process_chunky_dkg_result_inner(
        &self,
        resolver: &impl AptosMoveResolver,
        module_storage: &impl AptosModuleStorage,
        log_context: &AdapterLogSchema,
        session_id: SessionId,
        dkg_output: CertifiedChunkyDKGOutput,
    ) -> Result<(VMStatus, VMOutput), ExecutionFailure> {
```

**File:** aptos-move/aptos-vm/src/validator_txns/chunky_dkg.rs (L115-154)
```rust
        if metadata.epoch != config_resource.epoch() {
            return Err(ExecutionFailure::Expected(ExpectedFailure::EpochNotCurrent));
        }

        let validator_set = ValidatorSet::fetch_config(resolver).ok().flatten().ok_or(
            ExecutionFailure::Expected(ExpectedFailure::MissingResourceValidatorSet),
        )?;
        let chunky_dkg_state = ChunkyDKGState::fetch_config(resolver)
            .ok()
            .flatten()
            .ok_or(ExecutionFailure::Expected(
                ExpectedFailure::MissingResourceChunkyDKGState,
            ))?;

        let _in_progress_session_state =
            chunky_dkg_state
                .in_progress
                .as_ref()
                .ok_or(ExecutionFailure::Expected(
                    ExpectedFailure::MissingResourceInprogressChunkyDKGSession,
                ))?;

        let verifier = ValidatorVerifier::from(&validator_set);
        let authors = signature.get_signers_addresses(&verifier.get_ordered_account_addresses());

        // Check voting power.
        verifier
            .check_voting_power(authors.iter(), true)
            .map_err(|_| ExecutionFailure::Expected(ExpectedFailure::NotEnoughVotingPower))?;

        // TODO(ibalajiarun): Figure out how to verify without bcs deserialization
        let trx: AggregatedSubtranscript = bcs::from_bytes(&transcript_bytes).map_err(|_| {
            ExecutionFailure::Expected(ExpectedFailure::TranscriptDeserializationFailed)
        })?;
        if trx.dealer_epoch != metadata.epoch {
            return Err(ExecutionFailure::Expected(ExpectedFailure::EpochNotCurrent));
        }
        verifier
            .verify_multi_signatures(&trx, &signature)
            .map_err(|_| ExecutionFailure::Expected(ExpectedFailure::MultiSigVerificationFailed))?;
```

**File:** types/src/validator_txn.rs (L18-23)
```rust
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, CryptoHasher, BCSCryptoHash)]
pub enum ValidatorTransaction {
    DKGResult(DKGTranscript),
    ObservedJWKUpdate(jwks::QuorumCertifiedUpdate),
    ChunkyDKGResult(CertifiedChunkyDKGOutput),
}
```

**File:** dkg/src/chunky/dkg_manager/mod.rs (L596-614)
```rust
        let certified_transcript = CertifiedAggregatedChunkySubtranscript {
            metadata: DKGTranscriptMetadata {
                epoch: self.epoch_state.epoch,
                author: self.my_addr,
            },
            transcript_bytes,
            signature: aggregate_signature,
        };

        let txn = ValidatorTransaction::ChunkyDKGResult(CertifiedChunkyDKGOutput {
            certified_transcript,
            encryption_key: encryption_key_bytes,
        });
        // TODO(ibalajiarun): Derive Topic from txn
        let vtxn_guard = self.vtxn_pool.put(
            Topic::ChunkyDKG,
            Arc::new(txn),
            Some(self.pull_notification_tx.clone()),
        );
```
