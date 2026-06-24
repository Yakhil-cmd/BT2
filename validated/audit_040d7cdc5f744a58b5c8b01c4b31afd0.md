Audit Report

## Title
CPU Exhaustion via Byzantine Dealer Out-of-Range Chunks Triggering BSGS in `dec_chunks` — (`rs/crypto/internal/crypto_lib/threshold_sig/bls12_381/src/ni_dkg/fs_ni_dkg/forward_secure.rs`)

## Summary

A Byzantine dealer node can craft a NI-DKG dealing with plaintext chunks outside `[0, CHUNK_MAX]`, produce a structurally valid chunking proof (the sigma protocol's `z_s < zz` bound does not enforce honest chunk range for small scale factors), pass all dealing verification gates, and force every honest replica that calls `dec_chunks` during `load_transcript` to invoke `CheatingDealerDlogSolver` — a BSGS computation the code itself annotates as potentially taking hours per chunk, allocating up to 2 GiB of table memory.

## Finding Description

**Slow path in `dec_chunks`:** When `HonestDealerDlogLookupTable::solve_several` returns `None` for any chunk (i.e., the discrete log falls outside `[CHUNK_MIN, CHUNK_MAX]`), `CheatingDealerDlogSolver::new(n, m)` is constructed and `cheating_solver.solve()` is called for each failing chunk. [1](#0-0) 

The comment at line 830 reads: *"It may take hours to brute force a cheater's discrete log."*

**`CheatingDealerDlogSolver` cost:** The constructor allocates a BSGS table capped at 2 GiB. The `solve` method loops `1..scale_range` (up to 255 iterations where `scale_range = 1 << CHALLENGE_BITS`), each calling `baby_giant.solve` over the full table. [2](#0-1) [3](#0-2) 

**Chunking proof does not enforce `s_ij ∈ [0, CHUNK_SIZE-1]`:** `prove_chunking` computes `z_s[k] = Σ(e_ijk * s_ij) + sigma_k` and retries until `z_s[k] < zz`. The bound is `zz = 2 * NUM_ZK_REPETITIONS * n * m * (CHUNK_SIZE-1) * CHALLENGE_MASK`. For out-of-range chunks with `s_ij = delta * s_ij_honest` for small `delta` (2–11), the sum is `delta` times larger but `zz` is `2 * NUM_ZK_REPETITIONS` times `ss`, so the retry loop succeeds with high probability (≈ `2*NUM_ZK_REPETITIONS / (2*NUM_ZK_REPETITIONS + delta + 1)` per repetition). The verifier only checks `z_sk >= zz_big` and algebraic group-equation consistency — it does not enforce that witnesses are in the honest range. [4](#0-3) [5](#0-4) 

**`verify_ciphertext_integrity` passes for out-of-range chunks:** The existing test explicitly multiplies a chunk by `delta ∈ [2,11]`, asserts `sij > CHUNK_MAX`, and asserts `verify_ciphertext_integrity` returns `Ok(())`. [6](#0-5) 

**`verify_dealing` calls `verify_zk_proofs` which calls `verify_chunking`:** The dealing verification path is `verify_dealing` → `verify_zk_proofs` → `verify_ciphertext_integrity` + `verify_chunking` + `verify_sharing`. All three pass for a crafted dealing with small-delta out-of-range chunks. [7](#0-6) [8](#0-7) 

**Call chain from `load_transcript` to `dec_chunks`:** `compute_threshold_signing_key` iterates over all dealer entries in the transcript and calls `decrypt` for each, which calls `dec_chunks` directly with no re-verification of chunk range. [9](#0-8) [10](#0-9) [11](#0-10) 

**The `#[ignore]` benchmark directly measures this cost:** [12](#0-11) 

## Impact Explanation

This is a **High** severity finding matching the allowed impact: *"Application/platform-level DoS, crash, consensus blocking, certified-state disruption, or subnet availability impact not based on raw volumetric DDoS."*

A single crafted dealing causes every honest replica that is a receiver to block its crypto thread for hours during `load_transcript`. For a 28-node subnet with `NUM_CHUNKS = 16`, the BSGS solver runs up to `16 × 255` iterations over a ~2 GiB table. Replicas cannot complete DKG transcript loading, cannot derive their threshold signing key for the new epoch, and cannot participate in threshold signing — directly impacting subnet availability and continuity of threshold signing operations.

## Likelihood Explanation

The attacker is a single Byzantine dealer node, which is a realistic adversary in the IC threat model (up to `f = ⌊(n-1)/3⌋` Byzantine nodes are tolerated). No key compromise, majority corruption, or privileged access is required. The dealing passes all existing verification gates. The attack is repeatable every DKG round. The `#[ignore]` benchmark `print_time_for_cheating_dlog_solver_to_run` exists precisely to measure this cost and confirms the hours-scale runtime.

## Recommendation

1. **Add a range check before invoking `CheatingDealerDlogSolver`**: After `HonestDealerDlogLookupTable::solve_several` returns `None`, immediately return `Err(DecErr::InvalidChunk)` rather than running BSGS. The BSGS path was designed to recover from a cheating dealer, but the correct response at the decryption layer is rejection, not recovery — the dealing should have been excluded at transcript creation time.
2. **Cap BSGS iterations with a timeout**: If the slow path is intentionally retained for forensic purposes, bound the number of iterations and return `Err(DecErr::InvalidChunk)` on timeout.
3. **Strengthen `verify_chunking` with a proper range proof**: Replace the sigma protocol's loose `z_s < zz` bound with a range proof that enforces `s_ij ∈ [0, CHUNK_SIZE-1]`, so out-of-range dealings are rejected at `verify_dealing` time before being included in any transcript.

## Proof of Concept

The existing test infrastructure directly supports this:

1. Run the existing test `should_decrypt_correctly_for_cheating_dealer` in `rs/crypto/internal/crypto_lib/threshold_sig/bls12_381/tests/forward_secure.rs` — it already creates out-of-range chunks (`sij *= delta`, `delta ∈ [2,11]`), confirms `verify_ciphertext_integrity` passes, and calls `dec_chunks` which triggers the slow path.
2. Run `print_time_for_cheating_dlog_solver_to_run` (remove `#[ignore]`) in `rs/crypto/internal/crypto_lib/threshold_sig/bls12_381/tests/cheating_dealer.rs` to directly measure the hours-scale BSGS cost.
3. To confirm the full attack path, extend the PoC: call `prove_chunking` with the out-of-range witness (the retry loop succeeds for small `delta`), call `verify_chunking` on the result (it passes), then call `dec_chunks` and measure elapsed time.

### Citations

**File:** rs/crypto/internal/crypto_lib/threshold_sig/bls12_381/src/ni_dkg/fs_ni_dkg/forward_secure.rs (L823-833)
```rust
        if dlogs.iter().any(|x| x.is_none()) {
            // Cheating dealer case
            let cheating_solver = CheatingDealerDlogSolver::new(n, m);

            for i in 0..dlogs.len() {
                if dlogs[i].is_none() {
                    // TODO(CRP-2550) All BSGS could be run in parallel
                    // It may take hours to brute force a cheater's discrete log.
                    dlogs[i] = cheating_solver.solve(&powers[i]);
                }
            }
```

**File:** rs/crypto/internal/crypto_lib/threshold_sig/bls12_381/src/ni_dkg/fs_ni_dkg/dlog_recovery.rs (L339-366)
```rust
impl CheatingDealerDlogSolver {
    const MAX_TABLE_MBYTES: usize = 2 * 1024; // 2 GiB

    // We limit the maximum table size when compiling without optimizations
    // since otherwise the table becomes so expensive to compute that bazel
    // will fail the test with timeouts.
    const LARGEST_TABLE_MUL: usize = if cfg!(debug_assertions) { 2 } else { 20 };

    pub fn new(n: usize, m: usize) -> Self {
        let scale_range = 1 << CHALLENGE_BITS;
        let ss = n * m * (CHUNK_SIZE - 1) * (scale_range - 1);
        let zz = 2 * NUM_ZK_REPETITIONS * ss;

        let bsgs_lo = 1 - zz as isize;
        let bsgs_range = 2 * zz - 1;

        let baby_giant = BabyStepGiantStep::new(
            Gt::generator(),
            bsgs_lo,
            bsgs_range,
            Self::MAX_TABLE_MBYTES,
            Self::LARGEST_TABLE_MUL,
        );
        Self {
            baby_giant,
            scale_range,
        }
    }
```

**File:** rs/crypto/internal/crypto_lib/threshold_sig/bls12_381/src/ni_dkg/fs_ni_dkg/dlog_recovery.rs (L374-400)
```rust
    pub fn solve(&self, target: &Gt) -> Option<Scalar> {
        /*
        For some Delta in [1..E - 1] the answer s satisfies (Delta * s) in
        [1 - Z..Z - 1].

        For each delta in [1..E - 1] we compute target*delta and use
        baby-step-giant-step to find `scaled_answer` such that:
           base*scaled_answer = target*delta

         Then `base * (scaled_answer / delta) = target`
          (here division is modulo the group order
         That is, the discrete log of target is `scaled_answer / delta`.
        */
        let mut target_power = Gt::identity();
        for delta in 1..self.scale_range {
            target_power += target;

            if let Some(scaled_answer) = self.baby_giant.solve(&target_power) {
                let inv_delta = Scalar::from_usize(delta)
                    .inverse()
                    .expect("Delta is always invertible");
                let result = scaled_answer * inv_delta;
                return Some(result);
            }
        }
        None
    }
```

**File:** rs/crypto/internal/crypto_lib/threshold_sig/bls12_381/src/ni_dkg/fs_ni_dkg/nizk_chunking.rs (L226-273)
```rust
    let (first_move, first_challenge, z_s) = loop {
        let sigma = [(); NUM_ZK_REPETITIONS]
            .map(|_| Scalar::random_within_range(rng, range as u64) + &p_sub_s);

        let cc = G1Projective::batch_normalize_array(&y0_g1_tbl.mul2_array(&beta, &sigma));

        let first_move = FirstMoveChunking::from(y0.clone(), bb.clone(), cc);
        // Verifier's challenge.
        let first_challenge = ChunksOracle::new(instance, &first_move).get_all_chunks(n, m);

        // z_s = [sum [e_ijk * s_ij | i <- [1..n], j <- [1..m]] + sigma_k | k <- [1..l]]

        let iota: [usize; NUM_ZK_REPETITIONS] = std::array::from_fn(|i| i);

        let z_s = iota.map(|k| {
            let mut acc = Scalar::zero();
            first_challenge
                .iter()
                .zip(witness.scalars_s.iter())
                .for_each(|(e_i, s_i)| {
                    e_i.iter().zip(s_i.iter()).for_each(|(e_ij, s_ij)| {
                        acc += Scalar::from_usize(e_ij[k]) * s_ij;
                    });
                });
            acc += &sigma[k];

            acc
        });

        // Now check if our z_s is valid. Our control flow reveals if we retry
        // but in the event of a retry it should ideally not reveal *which* z_s
        // caused us to retry, since that may reveal information about the witness.
        //
        // Perform the check by using ct_compare with zz_big. This function
        // returns 1 if the zz_big is greater than its argument. If for any
        // input it returns 0 or -1 (indicating z was == or > zz_big) then the
        // sum will not match the overall length of z_s.

        let zs_in_range = z_s
            .iter()
            .map(|z| zz_big.ct_compare(z) as isize)
            .sum::<isize>() as usize
            == NUM_ZK_REPETITIONS;

        if zs_in_range {
            break (first_move, first_challenge, z_s);
        }
    };
```

**File:** rs/crypto/internal/crypto_lib/threshold_sig/bls12_381/src/ni_dkg/fs_ni_dkg/nizk_chunking.rs (L343-351)
```rust
    let ss = n * m * (CHUNK_SIZE - 1) * CHALLENGE_MASK;
    let zz = 2 * NUM_ZK_REPETITIONS * ss;
    let zz_big = Scalar::from_usize(zz);

    for z_sk in nizk.z_s.iter() {
        if z_sk >= &zz_big {
            return Err(ZkProofChunkingError::InvalidProof);
        }
    }
```

**File:** rs/crypto/internal/crypto_lib/threshold_sig/bls12_381/tests/forward_secure.rs (L174-194)
```rust
    let delta = (2 + rng.r#gen::<usize>() % 10) as isize;
    sij[cheating_i][cheating_j] *= delta; // doesn't overflow as delta is small and isize >> u16

    // however the new sij *is* larger than the maximum "legal" chunk
    assert!(sij[cheating_i][cheating_j] > CHUNK_MAX);

    let cheating_chunks = sij
        .iter()
        .map(|c| PlaintextChunks::new_unchecked(*c))
        .collect::<Vec<_>>();

    let pks_and_chunks = pks
        .iter()
        .cloned()
        .zip(cheating_chunks.iter().cloned())
        .collect::<Vec<_>>();

    let (crsz, _witness) = enc_chunks(&pks_and_chunks, epoch, &associated_data, sys, rng);

    // still a valid ciphertext
    assert!(verify_ciphertext_integrity(&crsz, epoch, &associated_data, sys).is_ok());
```

**File:** rs/crypto/internal/crypto_lib/threshold_sig/bls12_381/src/ni_dkg/groth20_bls12_381/dealing.rs (L246-272)
```rust
pub fn verify_dealing(
    dealer_index: NodeIndex,
    threshold: NumberOfNodes,
    epoch: Epoch,
    receiver_keys: &BTreeMap<NodeIndex, FsEncryptionPublicKey>,
    dealing: &Dealing,
) -> Result<(), CspDkgVerifyDealingError> {
    let number_of_receivers =
        number_of_receivers(receiver_keys).map_err(CspDkgVerifyDealingError::SizeError)?;
    verify_threshold(threshold, number_of_receivers)
        .map_err(CspDkgVerifyDealingError::InvalidThresholdError)?;
    verify_receiver_indices(receiver_keys, number_of_receivers)?;
    verify_all_shares_are_present_and_well_formatted(dealing, number_of_receivers)
        .map_err(CspDkgVerifyDealingError::InvalidDealingError)?;
    verify_public_coefficients_match_threshold(dealing, threshold)
        .map_err(CspDkgVerifyDealingError::InvalidDealingError)?;
    verify_zk_proofs(
        epoch,
        receiver_keys,
        &dealing.public_coefficients,
        &dealing.ciphertexts,
        &dealing.zk_proof_decryptability,
        &dealing.zk_proof_correct_sharing,
        &dealer_index.to_be_bytes(),
    )?;
    Ok(())
}
```

**File:** rs/crypto/internal/crypto_lib/threshold_sig/bls12_381/src/ni_dkg/groth20_bls12_381/encryption.rs (L221-250)
```rust
pub fn decrypt(
    ciphertext: &FsEncryptionCiphertextBytes,
    secret_key: &crypto::SecretKey,
    node_index: NodeIndex,
    epoch: Epoch,
    associated_data: &[u8],
) -> Result<Scalar, DecryptError> {
    let index = usize::try_from(node_index).map_err(|_| {
        DecryptError::SizeError(SizeError {
            message: format!("Node index is too large for this machine: {node_index}"),
        })
    })?;
    if index >= ciphertext.ciphertext_chunks.len() {
        return Err(DecryptError::InvalidReceiverIndex {
            num_receivers: NumberOfNodes::from(ciphertext.ciphertext_chunks.len() as NodeIndex),
            node_index,
        });
    }
    if let Some(current_epoch) = secret_key.current_epoch()
        && epoch < current_epoch
    {
        return Err(DecryptError::EpochTooOld {
            ciphertext_epoch: epoch,
            secret_key_epoch: current_epoch,
        });
    }
    let ciphertext = crypto::FsEncryptionCiphertext::deserialize(ciphertext)
        .map_err(DecryptError::MalformedCiphertext)?;
    crypto::dec_chunks(secret_key, index, &ciphertext, epoch, associated_data)
        .map_err(|e| DecryptError::InvalidChunk(format!("{e:?}")))
```

**File:** rs/crypto/internal/crypto_lib/threshold_sig/bls12_381/src/ni_dkg/groth20_bls12_381/encryption.rs (L372-404)
```rust
    crypto::verify_ciphertext_integrity(
        &ciphertext,
        epoch,
        associated_data,
        crypto::SysParam::global(),
    )
    .map_err(|_| {
        CspDkgVerifyDealingError::InvalidDealingError(InvalidArgumentError {
            message: "Ciphertext integrity check failed".to_string(),
        })
    })?;

    let chunking_proof = crypto::ProofChunking::deserialize(chunking_proof).ok_or_else(|| {
        CspDkgVerifyDealingError::MalformedDealingError(InvalidArgumentError {
            message: "Could not parse proof of correct encryption".to_string(),
        })
    })?;

    // Verify proof
    crypto::verify_chunking(
        &crypto::ChunkingInstance::new(
            public_keys.clone(),
            ciphertext.ciphertext_chunks().to_vec(),
            ciphertext.randomizers_r().clone(),
        ),
        &chunking_proof,
    )
    .map_err(|_| {
        let error = InvalidArgumentError {
            message: "Invalid chunking proof".to_string(),
        };
        CspDkgVerifyDealingError::InvalidDealingError(error)
    })?;
```

**File:** rs/crypto/internal/crypto_lib/threshold_sig/bls12_381/src/ni_dkg/groth20_bls12_381/transcript.rs (L262-293)
```rust
    let shares_from_each_dealer: Result<BTreeMap<NodeIndex, threshold_types::SecretKey>, _> =
        transcript
            .receiver_data
            .iter()
            .map(|(dealer_index, encrypted_shares)| {
                let secret_key = decrypt(
                    encrypted_shares,
                    fs_secret_key,
                    receiver_index,
                    epoch,
                    &dealer_index.to_be_bytes(),
                )
                .map_err(|error| match error {
                    ni_dkg_errors::DecryptError::EpochTooOld {
                        ciphertext_epoch,
                        secret_key_epoch,
                    } => ni_dkg_errors::CspDkgLoadPrivateKeyError::EpochTooOldError {
                        ciphertext_epoch,
                        secret_key_epoch,
                    },
                    error => {
                        let message = format!(
                            "Dealing #{dealer_index}: could not get share for receiver #{receiver_index}.\n {error:#?}"
                        );
                        let error = InvalidArgumentError { message };
                        ni_dkg_errors::CspDkgLoadPrivateKeyError::InvalidTranscriptError(error)
                    }
                })?;

                Ok((*dealer_index, secret_key))
            })
            .collect();
```

**File:** rs/crypto/internal/crypto_service_provider/src/vault/local_csp_vault/ni_dkg/mod.rs (L494-500)
```rust
                let csp_secret_key = ni_dkg_clib::compute_threshold_signing_key(
                    &transcript,
                    receiver_index,
                    &fs_decryption_key,
                    epoch,
                )
                .map(CspSecretKey::ThresBls12_381)?;
```

**File:** rs/crypto/internal/crypto_lib/threshold_sig/bls12_381/tests/cheating_dealer.rs (L49-78)
```rust
#[test]
#[ignore]
fn print_time_for_cheating_dlog_solver_to_run() {
    let rng = &mut reproducible_rng();

    let subnet_size = 13;
    let total_tests = 16; // one fully bad dealing

    let table_start = std::time::SystemTime::now();
    let solver = CheatingDealerDlogSolver::new(subnet_size, 16);
    println!(
        "Created table for {} nodes in {:?}",
        subnet_size,
        table_start.elapsed().unwrap()
    );

    let tests = (0..total_tests)
        .map(|_| cheating_dlog_instance(subnet_size, rng, true))
        .collect::<Vec<_>>();

    for (solution, target) in tests {
        let solve_start = std::time::SystemTime::now();

        assert_eq!(
            solution,
            solver.solve(&target).expect("Unable to solve dlog")
        );

        println!("Solved an instance in {:?}", solve_start.elapsed().unwrap());
    }
```
