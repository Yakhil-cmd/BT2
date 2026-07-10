Looking at the CKD protocol in `src/confidential_key_derivation/protocol.rs`, I can identify a clear analog to the missing-output-validation vulnerability class.

---

### Title
Malicious Participant Can Corrupt CKD Output Without Detection — (`File: src/confidential_key_derivation/protocol.rs`)

### Summary
The `do_ckd_coordinator` function accumulates per-participant contributions `(norm_big_y, norm_big_c)` with no cryptographic validation that each contribution was honestly computed. A single malicious participant can send arbitrary group elements, silently corrupting the final CKD output accepted by the coordinator and all honest parties.

### Finding Description

In `do_ckd_coordinator`, the coordinator receives each participant's `(norm_big_y, norm_big_c)` pair and blindly adds them: [1](#0-0) 

```rust
for (_, participant_output) in
    recv_from_others::<CKDOutput>(&chan, waitpoint, &participants, me).await?
{
    norm_big_y += participant_output.big_y();
    norm_big_c += participant_output.big_c();
}
```

Each honest participant is supposed to compute: [2](#0-1) 

- `big_y = y_i * G1` (random blinding point)
- `big_s = x_i * H(pk || app_id)` (secret share contribution in G1)
- `big_c = big_s + y_i * app_pk`
- `norm_big_y = lambda_i * big_y`, `norm_big_c = lambda_i * big_c`

The coordinator has no mechanism to verify that the received `norm_big_c` is consistent with the sender's known public key share, because:

1. `y_i` is ephemeral and private — the coordinator cannot reconstruct `y_i * G1` to check `norm_big_y`.
2. The participant's G2 public key share (`x_i * G2`) cannot be used to verify `x_i * H(pk, app_id)` in G1 without a pairing-based proof, which is absent.
3. No zero-knowledge proof of correct computation (e.g., DLEQ proof) is attached to the contribution.

There is no analog to the validation checks present in other protocols in this codebase, such as the `E =?= e*G` check in OT-based ECDSA presign: [3](#0-2) 

or the exponent interpolation consistency checks in robust ECDSA presign: [4](#0-3) 

The CKD protocol has no equivalent guard.

### Impact Explanation

A malicious participant sends an arbitrary `(norm_big_y', norm_big_c')` instead of the correct values. The coordinator computes:

```
final_big_y = honest_sum_big_y + norm_big_y'   (wrong)
final_big_c = honest_sum_big_c + norm_big_c'   (wrong)
```

The resulting `CKDOutput` is accepted by the coordinator as valid. When the TEE application calls `unmask(app_sk)` on this output, it recovers a value that is not `msk * H(pk, app_id)` — the derived confidential key is silently wrong. The TEE application has no way to detect this corruption because the CKD output carries no integrity proof.

This matches: **High — Corruption of CKD outputs so honest parties accept unusable cryptographic outputs.**

### Likelihood Explanation

Any single participant in the CKD protocol can trigger this. The `ckd()` entry point: [5](#0-4) 

accepts any registered participant as a caller. No additional trust assumption beyond holding a valid key share is required. The attack requires only sending a malformed message in the single protocol round — it is trivially reachable by any malicious participant.

### Recommendation

Add a proof of correct computation to each participant's contribution. Concretely, each participant should attach a DLEQ (Discrete Log Equality) proof demonstrating that the same scalar `y_i` was used in both `norm_big_y = lambda_i * y_i * G1` and the `y_i * app_pk` term inside `norm_big_c`. Additionally, a proof that `norm_big_c` encodes the correct secret-share contribution (consistent with the participant's public key share) should be required before the coordinator accumulates any value. The coordinator in `do_ckd_coordinator` must verify these proofs before calling `+= participant_output.big_y()` and `+= participant_output.big_c()`.

### Proof of Concept

1. Honest participants P1, P2, P3 run `ckd()` with coordinator P1.
2. P2 is malicious. Instead of computing `(norm_big_y, norm_big_c)` correctly, P2 sends `(ElementG1::identity(), ElementG1::identity())` (or any arbitrary point).
3. The coordinator at lines 50–55 adds P2's values without any check.
4. The final `CKDOutput` returned at line 56 is `CKDOutput::new(norm_big_y, norm_big_c)` where both components are shifted by P2's arbitrary contribution.
5. The TEE calls `ckd_output.unmask(app_sk)` and receives a value that differs from `msk * H(pk, app_id)` — the correct confidential key — with no error or indication of corruption. [6](#0-5)

### Citations

**File:** src/confidential_key_derivation/protocol.rs (L35-58)
```rust
async fn do_ckd_coordinator(
    mut chan: SharedChannel,
    participants: ParticipantList,
    me: Participant,
    key_pair: &KeygenOutput,
    app_id: &AppId,
    app_pk: PublicKey,
    rng: &mut impl CryptoRngCore,
) -> Result<CKDOutputOption, ProtocolError> {
    let (mut norm_big_y, mut norm_big_c) =
        compute_signature_share(&participants, me, key_pair, app_id, app_pk, rng)?;

    // Receive everyone's inputs and add them together
    let waitpoint = chan.next_waitpoint();

    for (_, participant_output) in
        recv_from_others::<CKDOutput>(&chan, waitpoint, &participants, me).await?
    {
        norm_big_y += participant_output.big_y();
        norm_big_c += participant_output.big_c();
    }
    let ckd_output = CKDOutput::new(norm_big_y, norm_big_c);
    Ok(Some(ckd_output))
}
```

**File:** src/confidential_key_derivation/protocol.rs (L66-101)
```rust
pub fn ckd(
    participants: &[Participant],
    coordinator: Participant,
    me: Participant,
    key_pair: KeygenOutput,
    app_id: impl Into<AppId>,
    app_pk: PublicKey,
    rng: impl CryptoRngCore + Send + 'static,
) -> Result<impl Protocol<Output = CKDOutputOption>, InitializationError> {
    // not enough participants
    if participants.len() < 2 {
        return Err(InitializationError::NotEnoughParticipants {
            participants: participants.len(),
        });
    }

    // kick out duplicates
    let Some(participants) = ParticipantList::new(participants) else {
        return Err(InitializationError::DuplicateParticipants);
    };

    // ensure my presence in the participant list
    if !participants.contains(me) {
        return Err(InitializationError::MissingParticipant {
            role: "self",
            participant: me,
        });
    }

    // ensure the coordinator is a participant
    if !participants.contains(coordinator) {
        return Err(InitializationError::MissingParticipant {
            role: "coordinator",
            participant: coordinator,
        });
    }
```

**File:** src/confidential_key_derivation/protocol.rs (L159-181)
```rust
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

**File:** src/ecdsa/ot_based_ecdsa/presign.rs (L125-131)
```rust
    // E =?= e*G
    // Spec 1.5
    if big_e != (ProjectivePoint::GENERATOR * e).to_affine() {
        return Err(ProtocolError::AssertionFailed(
            "received incorrect shares of kd".to_string(),
        ));
    }
```

**File:** src/ecdsa/robust_ecdsa/presign.rs (L193-212)
```rust
    // check that the exponent interpolations match what has been received
    for (identifier, verifying_share) in identifiers
        .iter()
        .skip(threshold + 1)
        .zip(verifying_shares.iter().skip(threshold + 1))
    {
        // Step 3.2
        // exponent interpolation for (R0, .., Rt; i)
        let big_r_i = PolynomialCommitment::eval_exponent_interpolation(
            threshold_plus1_identifiers,
            threshold_plus1_verifying_shares,
            Some(identifier),
        )?;

        // check the interpolated R values match the received ones
        if big_r_i != *verifying_share {
            return Err(ProtocolError::AssertionFailed(
                "Exponent interpolation check failed.".to_string(),
            ));
        }
```
