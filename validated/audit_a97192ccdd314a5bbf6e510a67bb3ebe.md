Audit Report

## Title
VetKD Byzantine Node Triggers O(n) Pairing Fallback Per Request via Cryptographically Invalid Share with Valid Node Signature — (`rs/crypto/src/vetkd/mod.rs`)

## Summary
`verify_encrypted_key_share_internal` only verifies the node's basic signature over the raw share bytes and never calls `EncryptedKeyShare::is_valid`, so a Byzantine subnet node can submit a share with a valid node signature but cryptographically invalid `c1`/`c2`/`c3` values that passes admission into the validated pool. When `combine_encrypted_key_shares` is called with all n shares (VetKD collects all n, not threshold+1), `combine_all` fails with `InvalidShares`, triggering a fallback that computes individual public keys for every node and performs up to O(n) × 5 BLS12-381 pairing operations per request instead of the normal 5. The attack is repeatable on every VetKD request by a single Byzantine node below the fault threshold.

## Finding Description

**Root cause — share verification skips cryptographic validity:**

`verify_encrypted_key_share_internal` in `rs/crypto/src/vetkd/mod.rs` (L272–302) calls only `BasicSigVerifierInternal::verify_basic_sig` over the raw share bytes. It never invokes `EncryptedKeyShare::is_valid`, so a share whose `c1`/`c2`/`c3` points are structurally valid elliptic-curve points but cryptographically inconsistent (e.g., `c1` and `c3` swapped) passes verification and is admitted to the validated pool. [1](#0-0) 

**All n shares are collected for VetKD (not threshold+1):**

`rs/consensus/idkg/src/signer.rs` L1417 explicitly sets `expected_nb_sig_shares = n` for VetKD, meaning all n shares (including the Byzantine one) are validated and passed to the combiner. [2](#0-1) 

**`combine_all` interpolates over all n shares; one invalid share poisons the result:**

`EncryptedKey::combine_all` calls `combine_unchecked`, which performs Lagrange interpolation over the entire `nodes` map. If any share is invalid, the interpolated key fails `is_valid`, returning `EncryptedKeyCombinationError::InvalidShares`. [3](#0-2) 

**`InvalidShares` fallback iterates all n nodes with O(n) pairing cost:**

On `InvalidShares`, `combine_encrypted_key_shares_internal` (L388–430) iterates over the full `clib_shares` vector (all n nodes), calling `lazily_calculated_public_key_from_store` for each, then passes all n `(G2Affine, EncryptedKeyShare)` pairs to `combine_valid_shares`. [4](#0-3) 

`combine_valid_shares` then calls `EncryptedKeyShare::is_valid` (→ `check_validity`) for each node until `reconstruction_threshold` valid shares are found. `check_validity` performs two `Gt::multipairing` calls totalling 5 pairings per share. [5](#0-4) [6](#0-5) 

**Existing test confirms the fallback path is reachable:**

`should_succeed_if_reconstruction_threshold_many_shares_are_valid` in `rs/crypto/tests/vetkd.rs` (L370–403) explicitly corrupts shares by swapping `c1`/`c3` and asserts the fallback log message is emitted, confirming the path is exercised in the test suite and reachable in production. [7](#0-6) 

## Impact Explanation

This matches the allowed High impact: **"Application/platform-level DoS, crash, consensus blocking, certified-state disruption, or subnet availability impact not based on raw volumetric DDoS."**

For a 34-node subnet (threshold=23):
- Normal path: 5 pairings per request
- Attack path: up to (34 − 23 + 1) × 5 + 5 = 65 pairings per request (~13× amplification)

At ~1–2 ms per BLS12-381 pairing, the combiner's crypto thread spends ~65–130 ms per VetKD request instead of ~5–10 ms. Because the Byzantine node can submit one invalid share per request indefinitely, this is a sustained per-request throughput degradation of VetKD key delivery, scaling with subnet size.

## Likelihood Explanation

The attack requires only a single Byzantine subnet node operating below the BFT fault threshold — a realistic adversary. The technique (swapping `c1`/`c3` to produce a structurally valid but cryptographically invalid share, then re-signing with the node's key) is explicitly demonstrated in the existing test suite. No special access, key material, or coordination beyond normal subnet membership is required. The attack is repeatable on every VetKD request with no cooldown.

## Recommendation

Add cryptographic share validity verification inside `verify_encrypted_key_share_internal`. After verifying the basic node signature, also call `EncryptedKeyShare::is_valid` using the node's individual public key (computed via `lazily_calculated_public_key_from_store`). This ensures only cryptographically valid shares are admitted to the validated pool, preventing the `InvalidShares` fallback from being triggered by a Byzantine node.

As a secondary defense, the fallback path in `combine_encrypted_key_shares_internal` could track nodes that have previously submitted invalid shares and exclude them from future combination attempts, limiting repeated amplification even if admission-time checking is not added immediately.

## Proof of Concept

The existing test `should_succeed_if_reconstruction_threshold_many_shares_are_valid` in `rs/crypto/tests/vetkd.rs` (L370–403) already demonstrates the full attack path:

1. Create a VetKD test server with n nodes and threshold t.
2. Generate valid shares for all n nodes.
3. Corrupt `(n − t)` shares by swapping `c1`/`c3` bytes (structurally valid points, cryptographically invalid).
4. Call `combine_key_shares` with all n shares (including corrupted ones).
5. Assert success (fallback path recovers) AND assert the log contains `"EncryptedKey::combine_all failed with InvalidShares, falling back to EncryptedKey::combine_valid_shares"`.

To demonstrate the per-request amplification, extend the test to:
- Corrupt exactly 1 share (Byzantine node scenario).
- Instrument or time `combine_key_shares` to count pairing operations.
- Assert ~65 pairings are performed vs. ~5 in the uncorrupted baseline.
- Repeat the call in a loop to confirm the fallback is triggered on every invocation.

### Citations

**File:** rs/crypto/src/vetkd/mod.rs (L292-301)
```rust
    let signature = BasicSigOf::new(BasicSig(key_share.node_signature.clone()));
    BasicSigVerifierInternal::verify_basic_sig(
        csp_signer,
        registry,
        &signature,
        &key_share.encrypted_key_share,
        signer,
        registry_version_from_store,
    )
    .map_err(VetKdKeyShareVerificationError::VerificationError)
```

**File:** rs/crypto/src/vetkd/mod.rs (L388-415)
```rust
        Err(EncryptedKeyCombinationError::InvalidShares) => {
            info!(logger, "EncryptedKey::combine_all failed with InvalidShares, \
                falling back to EncryptedKey::combine_valid_shares"
            );

            let clib_shares_for_combine_valid: BTreeMap<NodeIndex, (G2Affine, EncryptedKeyShare)> = clib_shares
                .into_iter()
                .map(|(node_id, node_index, clib_share)| {
                    let node_public_key = lazily_calculated_public_key_from_store(
                        lockable_threshold_sig_data_store,
                        threshold_sig_csp_client,
                        args.ni_dkg_id,
                        node_id,
                    )
                    .map_err(|e| {
                        VetKdKeyShareCombinationError::IndividualPublicKeyComputationError(e)
                    })?;
                    let node_public_key_g2affine = match node_public_key {
                        CspThresholdSigPublicKey::ThresBls12_381(public_key_bytes) => {
                            G2Affine::deserialize_cached(&public_key_bytes.0)
                            .map_err(|_: PairingInvalidPoint| VetKdKeyShareCombinationError::InternalError(
                                format!("individual public key of node with ID {node_id} in threshold sig data store")
                            ))
                        }
                    }?;
                    Ok((node_index, (node_public_key_g2affine, clib_share.clone())))
                })
                .collect::<Result<_, _>>()?;
```

**File:** rs/consensus/idkg/src/signer.rs (L1414-1418)
```rust
        let expected_nb_sig_shares = match key_id {
            MasterPublicKeyId::Ecdsa(_) => get_faults_tolerated(n) + 1,
            MasterPublicKeyId::Schnorr(_) => get_faults_tolerated(n) + 1,
            MasterPublicKeyId::VetKd(_) => n, // The optimization is disabled for VetKD for now
        };
```

**File:** rs/crypto/internal/crypto_lib/bls12_381/vetkd/src/lib.rs (L157-188)
```rust
fn check_validity(
    c1: &G1Affine,
    c2: &G2Affine,
    c3: &G1Affine,
    tpk: &TransportPublicKey,
    verification_pk: &G2Affine,
    msg: &G1Affine,
) -> bool {
    let neg_g2_g = G2Prepared::neg_generator();
    let c2_prepared = G2Prepared::from(c2);

    // check e(c1,g2) == e(g1, c2)
    let c1_c2 = Gt::multipairing(&[(c1, neg_g2_g), (G1Affine::generator(), &c2_prepared)]);
    if !c1_c2.is_identity() {
        return false;
    }

    let verification_key_prepared = G2Prepared::from(verification_pk);

    // check e(c3, g2) == e(tpk, c2) * e(msg, dpki)
    let c3_c2_msg = Gt::multipairing(&[
        (c3, neg_g2_g),
        (tpk.point(), &c2_prepared),
        (msg, &verification_key_prepared),
    ]);

    if !c3_c2_msg.is_identity() {
        return false;
    }

    true
}
```

**File:** rs/crypto/internal/crypto_lib/bls12_381/vetkd/src/lib.rs (L252-266)
```rust
    pub fn combine_all(
        nodes: &BTreeMap<NodeIndex, EncryptedKeyShare>,
        reconstruction_threshold: usize,
        master_pk: &G2Affine,
        tpk: &TransportPublicKey,
        context: &DerivationContext,
        input: &[u8],
    ) -> Result<Self, EncryptedKeyCombinationError> {
        let c = Self::combine_unchecked(nodes, reconstruction_threshold)?;
        if c.is_valid(master_pk, context, input, tpk) {
            Ok(c)
        } else {
            Err(EncryptedKeyCombinationError::InvalidShares)
        }
    }
```

**File:** rs/crypto/internal/crypto_lib/bls12_381/vetkd/src/lib.rs (L286-299)
```rust
        // Take the first reconstruction_threshold shares which pass validity check
        let mut valid_shares = BTreeMap::new();

        for (node_index, (node_pk, node_eks)) in nodes.iter() {
            if node_eks.is_valid(master_pk, node_pk, context, input, tpk) {
                valid_shares.insert(*node_index, node_eks.clone());

                // Have we collected enough shares?
                // If so stop verifying and proceed with reconstruction
                if valid_shares.len() >= reconstruction_threshold {
                    break;
                }
            }
        }
```

**File:** rs/crypto/tests/vetkd.rs (L370-403)
```rust
    #[test]
    fn should_succeed_if_reconstruction_threshold_many_shares_are_valid() {
        let mut rng = reproducible_rng();
        let mut server = VetKDTestServer::new(&mut rng);
        let client = VetKDTestClient::new(&mut rng, &server);
        let vetkd_args = client.create_args(&server.dkg_id);

        let mut shares = server
            .create_key_shares(&vetkd_args, &mut rng)
            .expect("Share creation unexpectedly failed");

        let to_corrupt = shares.len() - server.config.threshold().get().get() as usize;

        modify_n_random_shares(to_corrupt, &mut shares, &mut rng, |share, _rng| {
            swap_share_c1c3(&mut share.encrypted_key_share);
        });

        match server.combine_key_shares(&shares, &vetkd_args, &mut rng) {
            Ok((combiner, _key)) => {
                /* expected success */
                let logger = server
                    .env
                    .loggers
                    .remove(&combiner)
                    .expect("Missing loggers");
                let logs = logger.drain_logs();
                LogEntriesAssert::assert_that(logs).has_only_one_message_containing(
                &Level::Info,
                "EncryptedKey::combine_all failed with InvalidShares, falling back to EncryptedKey::combine_valid_shares"
            );
            }
            Err(e) => panic!("Combination failed {:?}", e),
        }
    }
```
