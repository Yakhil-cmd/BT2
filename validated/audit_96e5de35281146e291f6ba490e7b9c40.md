### Title
Missing Verification of Participant Contributions in CKD Protocol Allows Malicious Participant to Corrupt Output — (`src/confidential_key_derivation/protocol.rs`)

### Summary
The `do_ckd_coordinator` function in the CKD protocol aggregates participant contributions `(norm_big_y, norm_big_c)` without any cryptographic verification that each contribution is correctly formed. Analogous to the missing token approval before `depositAsset` in the external report, this is a missing prerequisite validation step before a critical aggregation operation. A single malicious participant can send arbitrary group elements, silently corrupting the CKD output accepted by all honest parties.

### Finding Description

In `do_ckd_coordinator` (`src/confidential_key_derivation/protocol.rs`, lines 50–55), the coordinator receives each participant's `CKDOutput` and unconditionally accumulates it:

```rust
for (_, participant_output) in
    recv_from_others::<CKDOutput>(&chan, waitpoint, &participants, me).await?
{
    norm_big_y += participant_output.big_y();
    norm_big_c += participant_output.big_c();
}
```

Each honest participant computes their contribution in `compute_signature_share` (lines 148–181) as:

- `big_y = y * G` (random blinding point)
- `big_c = x_i * H(pk, app_id) + y * app_pk` (ElGamal-style ciphertext share)
- Both are then Lagrange-normalized: `norm_big_y = λ_i * big_y`, `norm_big_c = λ_i * big_c`

The coordinator is supposed to aggregate these so that `C - app_sk * Y = msk * H(pk, app_id)`. However, **no ZK proof or consistency check is required or verified** before adding a participant's `(norm_big_y, norm_big_c)` to the running sum. There is no proof that:

1. `norm_big_y` is `λ_i * y_i * G` for any `y_i` the participant actually used.
2. `norm_big_c` encodes the participant's legitimate key share `x_i` under the correct `app_pk`.

Compare this to the DKG protocol (`src/dkg.rs`, lines 452–522), which calls `verify_proof_of_knowledge` and `validate_received_share` before incorporating any participant's material. The CKD protocol has no equivalent prerequisite verification step.

The attack path is straightforward:
1. A malicious participant calls `ckd(...)` with valid inputs but, instead of computing the correct `(norm_big_y, norm_big_c)`, sends arbitrary group elements `(P, Q)` to the coordinator.
2. The coordinator's loop at lines 50–55 adds `P` and `Q` to the aggregate without any check.
3. The resulting `CKDOutput` is cryptographically invalid: `C - app_sk * Y ≠ msk * H(pk, app_id)`.
4. The coordinator returns this corrupted output as `Some(ckd_output)`, and all honest parties accept it.

### Impact Explanation

**High — Corruption of CKD outputs so honest parties accept unusable cryptographic outputs.**

The CKD protocol's purpose is to allow a threshold of participants to derive a deterministic confidential key `msk * H(pk, app_id)` for a TEE application without reconstructing the master secret. A single malicious participant can corrupt this output, causing the coordinator to return a `CKDOutput` that, when unmasked with `app_sk`, yields a random/wrong value instead of the correct confidential key. The honest coordinator and all downstream consumers accept this corrupted output with no indication of failure.

### Likelihood Explanation

Any participant in a CKD session can exploit this with no special privileges. The attacker only needs to be a valid member of the `participants` list (a normal protocol role). The attack requires sending two arbitrary `G1` points instead of the correct contribution — trivially achievable by any participant implementation.

### Recommendation

Before accumulating each participant's contribution, the coordinator must verify that the contribution is correctly formed. This requires participants to accompany their `(norm_big_y, norm_big_c)` with a ZK proof of correct construction — specifically, a proof of knowledge that there exists a scalar `y_i` such that `norm_big_y = λ_i * y_i * G` and `norm_big_c - λ_i * x_i * H(pk, app_id) = λ_i * y_i * app_pk` (a discrete-log equality proof across two bases, analogous to the `dlogeq` proofs already present in `src/crypto/proofs/dlogeq.rs`). The coordinator should call the equivalent of `dlogeq::verify` on each received contribution before adding it to the aggregate, mirroring the pattern used in `validate_received_share` during DKG.

### Proof of Concept

```
Honest setup: participants = [P1, P2, P3], coordinator = P1
P2 is malicious.

1. P1 and P3 compute correct (norm_big_y, norm_big_c) per compute_signature_share().
2. P2 sends (G1::identity(), G1::generator()) — arbitrary garbage — to P1 (coordinator).
3. do_ckd_coordinator lines 50-55 adds P2's garbage unconditionally:
       norm_big_y += G1::identity()   // no-op on Y
       norm_big_c += G1::generator()  // corrupts C by adding G
4. CKDOutput { big_y: Y_correct, big_c: C_correct + G } is returned as Some(...).
5. ckd_output.unmask(app_sk) = (C_correct + G) - app_sk * Y_correct
                              = msk * H(pk, app_id) + G   ← wrong key, no error raised.
``` [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3)

### Citations

**File:** src/confidential_key_derivation/protocol.rs (L50-55)
```rust
    for (_, participant_output) in
        recv_from_others::<CKDOutput>(&chan, waitpoint, &participants, me).await?
    {
        norm_big_y += participant_output.big_y();
        norm_big_c += participant_output.big_c();
    }
```

**File:** src/confidential_key_derivation/protocol.rs (L148-181)
```rust
fn compute_signature_share(
    participants: &ParticipantList,
    me: Participant,
    key_pair: &KeygenOutput,
    app_id: &AppId,
    app_pk: PublicKey,
    rng: &mut impl CryptoRngCore,
) -> Result<(ElementG1, ElementG1), ProtocolError> {
    // Ensures the value is zeroized on drop
    let private_share = Zeroizing::new(key_pair.private_share);

    // y <- ZZq* , Y <- y * G
    let y = Scalar::random(rng);

    // Ensures the value is zeroized on drop
    let y = Zeroizing::new(super::scalar_wrapper::ScalarWrapper(y));

    let big_y = ElementG1::generator() * y.0;

    // H(pk || app_id) when H is a random oracle
    let hash_point = hash_app_id_with_pk(&key_pair.public_key, app_id);

    // S <- x . H(app_id)
    let big_s = hash_point * private_share.to_scalar();

    // C <- S + y . A
    let big_c = big_s + app_pk * y.0;

    // Compute  λi := λi(0)
    let lambda_i = participants.lagrange::<BLS12381SHA256>(me)?;
    // Normalize Y and C into  (λi . Y , λi . C)
    let norm_big_y = big_y * lambda_i;
    let norm_big_c = big_c * lambda_i;
    Ok((norm_big_y, norm_big_c))
```

**File:** src/dkg.rs (L452-460)
```rust
        verify_proof_of_knowledge(
            &session_id,
            &mut proof_domain_separator.clone(), // you want to have the same state
            threshold,
            p,
            old_participants.clone(),
            commitment_i,
            proof_i.as_ref(),
        )?;
```

**File:** src/dkg.rs (L517-522)
```rust
        // Verify the share
        // this deviates from the original FROST DKG paper
        // however it matches the FROST implementation of ZCash
        let full_commitment_from = all_full_commitments.index(from)?;
        // Step 5.2
        validate_received_share::<C>(me, from, &signing_share_from, full_commitment_from)?;
```
