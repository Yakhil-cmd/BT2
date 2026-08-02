No vulnerability found for this question.

**Why the premise is incorrect:** The claim assumes `verify_transcript` only performs "structural validity" checks and lacks a dealer-set membership check tied to `dkg_node.metadata.author`. In reality, `DefaultDKG::verify_transcript` (i.e. `RealDKG::verify_transcript`) enforces dealer-set membership cryptographically, independent of `dkg_node.metadata.author`:

- `pub_params` is built by `DefaultDKG::new_public_params(&in_progress_session_state.metadata)`, which constructs `params.verifier` from the trusted, on-chain `dealer_consensus_infos_cloned()` of the in-progress session — not from any attacker-supplied field. [1](#0-0) 

- `verify_transcript` maps the transcript's internal dealer indices (`trx.main.get_dealers()`) to addresses using `params.verifier.get_ordered_account_addresses()` (the trusted session dealer set), then looks up each dealer's real BLS public key via `params.verifier.get_public_key(author)`, and finally calls the cryptographic `trx.main.verify(...)` (SoK/PVSS verification) using those keys. [2](#0-1) 

Because the transcript's authenticity is checked against real dealers' consensus public keys via proof-of-knowledge/PVSS verification, an attacker cannot forge a transcript that verifies successfully for a dealer index/address they don't control the private key for — regardless of what `dkg_node.metadata.author` says. `dkg_node.metadata.author` in `process_dkg_result_inner` is only used to check epoch freshness against `config_resource.epoch()`, not as part of the dealer-membership authorization logic. [3](#0-2) 

The `author` field is actually security-relevant in the off-chain peer-to-peer aggregation path (`TranscriptAggregationState::add`), where it's explicitly cross-checked against the sending peer (`ensure!(metadata.author == sender, ...)`) before the same cryptographic `verify_transcript` is invoked — but that's a separate, off-chain-to-onchain pipeline, not the final VM admission check in question. [4](#0-3) 

Since the actual dealer-set enforcement in the VM path is cryptographic (tied to the trusted session's validator keys) rather than a metadata string comparison, there is no way for an "unlisted dealer's transcript" to pass `verify_transcript` without possessing a legitimate dealer's private signing key — which falls outside the unprivileged-attacker threat model required by this review.

### Citations

**File:** types/src/dkg/real_dkg/mod.rs (L196-221)
```rust
    fn new_public_params(dkg_session_metadata: &DKGSessionMetadata) -> RealDKGPublicParams {
        let randomness_config = dkg_session_metadata
            .randomness_config_derived()
            .unwrap_or_else(OnChainRandomnessConfig::default_enabled);
        let secrecy_threshold = randomness_config
            .secrecy_threshold()
            .unwrap_or_else(|| *rounding::DEFAULT_SECRECY_THRESHOLD);
        let reconstruct_threshold = randomness_config
            .reconstruct_threshold()
            .unwrap_or_else(|| *rounding::DEFAULT_RECONSTRUCT_THRESHOLD);
        let maybe_fast_path_secrecy_threshold = randomness_config.fast_path_secrecy_threshold();

        let pvss_config = build_dkg_pvss_config(
            dkg_session_metadata.dealer_epoch,
            secrecy_threshold,
            reconstruct_threshold,
            maybe_fast_path_secrecy_threshold,
            &dkg_session_metadata.target_validator_consensus_infos_cloned(),
        );
        let verifier = ValidatorVerifier::new(dkg_session_metadata.dealer_consensus_infos_cloned());
        RealDKGPublicParams {
            session_metadata: dkg_session_metadata.clone(),
            pvss_config,
            verifier: verifier.into(),
        }
    }
```

**File:** types/src/dkg/real_dkg/mod.rs (L307-352)
```rust
    fn verify_transcript(
        params: &Self::PublicParams,
        trx: &Self::Transcript,
    ) -> anyhow::Result<()> {
        // Verify dealer indices are valid.
        let dealers = trx
            .main
            .get_dealers()
            .iter()
            .map(|player| player.id)
            .collect::<Vec<usize>>();
        let num_validators = params.session_metadata.dealer_validator_set.len();
        ensure!(
            dealers.iter().all(|id| *id < num_validators),
            "real_dkg::verify_transcript failed with invalid dealer index."
        );

        let all_eks = params.pvss_config.eks.clone();

        let addresses = params.verifier.get_ordered_account_addresses();
        let dealers_addresses = dealers
            .iter()
            .filter_map(|&pos| addresses.get(pos))
            .cloned()
            .collect::<Vec<_>>();

        let spks = dealers_addresses
            .iter()
            .filter_map(|author| params.verifier.get_public_key(author))
            .collect::<Vec<_>>();

        let aux = dealers_addresses
            .iter()
            .map(|address| (params.pvss_config.epoch, address))
            .collect::<Vec<_>>();

        trx.main.verify(
            &params.pvss_config.wconfig,
            &params.pvss_config.pp,
            &spks,
            &all_eks,
            &aux,
        )?;

        Ok(())
    }
```

**File:** aptos-move/aptos-vm/src/validator_txns/dkg.rs (L103-116)
```rust
        // Check epoch number.
        if dkg_node.metadata.epoch != config_resource.epoch() {
            return Err(Expected(EpochNotCurrent));
        }

        // Deserialize transcript and verify it.
        let pub_params = DefaultDKG::new_public_params(&in_progress_session_state.metadata);
        let transcript = bcs::from_bytes::<<DefaultDKG as DKGTrait>::Transcript>(
            dkg_node.transcript_bytes.as_slice(),
        )
        .map_err(|_| Expected(TranscriptDeserializationFailed))?;

        DefaultDKG::verify_transcript(&pub_params, &transcript)
            .map_err(|_| Expected(TranscriptVerificationFailed))?;
```

**File:** dkg/src/transcript_aggregation/mod.rs (L79-110)
```rust
        let peer_power = self.epoch_state.verifier.get_voting_power(&sender);
        ensure!(
            peer_power.is_some(),
            "[DKG] adding peer transcript failed with illegal dealer"
        );
        ensure!(
            metadata.author == sender,
            "[DKG] adding peer transcript failed with node author mismatch"
        );

        let session_max = S::expected_max_transcript_size(&self.dkg_pub_params);
        ensure!(
            transcript_bytes.len() <= session_max,
            "[DKG] adding peer transcript failed: transcript size {} exceeds max {}",
            transcript_bytes.len(),
            session_max,
        );

        let transcript = bcs::from_bytes(transcript_bytes.as_slice()).map_err(|e| {
            anyhow!("[DKG] adding peer transcript failed with trx deserialization error: {e}")
        })?;
        let mut trx_aggregator = self.trx_aggregator.lock();
        if trx_aggregator.contributors.contains(&metadata.author) {
            return Ok(None);
        }

        S::verify_transcript_extra(&transcript, &self.epoch_state.verifier, false, Some(sender))
            .context("extra verification failed")?;

        S::verify_transcript(&self.dkg_pub_params, &transcript).map_err(|e| {
            anyhow!("[DKG] adding peer transcript failed with trx verification failure: {e}")
        })?;
```
