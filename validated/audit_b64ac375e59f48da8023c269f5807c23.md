### Title
Missing Proof of Correctness for Participant Contributions in CKD Protocol Allows Malicious Participant to Corrupt CKD Output — (File: src/confidential_key_derivation/protocol.rs)

---

### Summary

The CKD coordinator blindly aggregates `(norm_big_y, norm_big_c)` contributions from participants with no proof of correctness. A single malicious participant can inject arbitrary non-identity G1 points, causing the coordinator to produce a corrupted CKD output that honest parties accept as valid, permanently derailing the confidential key derivation for that session.

---

### Finding Description

In `do_ckd_coordinator` the coordinator collects each participant's share and sums them unconditionally:

```rust
for (_, participant_output) in
    recv_from_others::<CKDOutput>(&chan, waitpoint, &participants, me).await?
{
    norm_big_y += participant_output.big_y();
    norm_big_c += participant_output.big_c();
}
let ckd_output = CKDOutput::new(norm_big_y, norm_big_c);
``` [1](#0-0) 

The honest computation each participant is supposed to perform is:

```
norm_big_y_i = λ_i · y_i · G
norm_big_c_i = λ_i · (x_i · H(pk ‖ app_id) + y_i · app_pk)
``` [2](#0-1) 

No zero-knowledge proof, commitment, or consistency check is attached to the sent pair. The only guard in the entire pipeline is the G1 deserializer, which rejects the identity point:

```rust
if point.is_identity().into() {
    Err(frost_core::GroupError::InvalidIdentityElement)
``` [3](#0-2) 

Any non-identity crafted point passes deserialization and is silently folded into the aggregate. There is no analogue of the commitment-then-reveal or Schnorr proof-of-knowledge checks that protect the DKG round: [4](#0-3) 

The root cause is structurally identical to the oracle report: values received from an external source (participants) are consumed directly without cross-validation or proof of origin.

---

### Impact Explanation

The aggregated output `(norm_big_y, norm_big_c)` is an ElGamal-style ciphertext of `msk · H(pk ‖ app_id)` under `app_pk`. When a malicious participant substitutes arbitrary points `(Δ_Y, Δ_C)`, the coordinator computes:

```
norm_big_y' = correct_Y + Δ_Y
norm_big_c' = correct_C + Δ_C
```

The application then unmasks as:

```
derived_key = norm_big_c' − app_sk · norm_big_y'
            = msk·H(pk‖app_id) + (Δ_C − app_sk·Δ_C)
```

The result is a wrong G1 point that is not the intended confidential key. Because the coordinator has no way to detect the manipulation, it returns the corrupted `CKDOutput` as if it were valid. Honest parties accept an unusable cryptographic output — matching the **High** impact tier: *Corruption of CKD outputs so honest parties accept unusable cryptographic outputs*.

---

### Likelihood Explanation

Any single participant in the CKD session can mount this attack. The participant need only serialize two arbitrary non-identity G1 points and send them in place of the honest `(norm_big_y, norm_big_c)`. No cryptographic capability beyond participation in the protocol is required. The attack is undetectable by the coordinator and leaves no forensic trace identifying the culprit, because no per-participant commitment is recorded.

---

### Recommendation

Attach a Schnorr proof of knowledge to each participant's contribution proving that `norm_big_y` is of the form `λ_i · y_i · G` for a known `y_i`, and that `norm_big_c` is consistently formed. This is the same pattern already used in the DKG to bind polynomial commitments to proofs of knowledge before they are accepted: [5](#0-4) 

Alternatively, adopt a verifiable ElGamal scheme where each participant's ciphertext is accompanied by a DLEQ proof tying `norm_big_y` and `norm_big_c` to the participant's public key share.

---

### Proof of Concept

1. Participant `P_malicious` is a legitimate member of the CKD session.
2. Instead of calling `compute_signature_share`, `P_malicious` constructs:
   - `norm_big_y = G1::generator()` (any non-identity point)
   - `norm_big_c = G1::generator()`
3. It serializes these as a `CKDOutput` and sends them to the coordinator at the expected waitpoint.
4. The coordinator's deserializer accepts both points (non-identity), adds them to the running sum, and returns `CKDOutput::new(corrupted_Y, corrupted_C)`.
5. The application calls `ckd_output.unmask(app_sk)` and obtains `msk·H(pk‖app_id) + (G − app_sk·G)` — a point that is not the intended confidential key and cannot be used for its purpose.
6. No error is raised; honest parties have no indication the output is wrong. [6](#0-5) [7](#0-6)

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

**File:** src/confidential_key_derivation/protocol.rs (L148-182)
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
}
```

**File:** src/confidential_key_derivation/ciphersuite.rs (L162-164)
```rust
                if point.is_identity().into() {
                    Err(frost_core::GroupError::InvalidIdentityElement)
                } else {
```

**File:** src/dkg.rs (L143-165)
```rust
/// Verifies the proof of knowledge of the secret coefficients used to generate the
/// public secret sharing commitment.
fn internal_verify_proof_of_knowledge<C: Ciphersuite>(
    session_id: &HashOutput,
    domain_separator: &mut DomainSeparator,
    participant: Participant,
    commitment: &VerifiableSecretSharingCommitment<C>,
    proof_of_knowledge: &Signature<C>,
) -> Result<(), ProtocolError> {
    // creates an identifier for the participant
    let id = participant.scalar::<C>();
    let vk_share = commitment
        .coefficients()
        .first()
        .ok_or_else(|| ProtocolError::AssertionFailed("Empty coefficient list".to_string()))?;

    let big_r = proof_of_knowledge.R();
    let z = proof_of_knowledge.z();
    let c = challenge::<C>(domain_separator, session_id, id, vk_share, big_r)?;
    if *big_r != <C::Group>::generator() * *z - vk_share.value() * c.to_scalar() {
        return Err(ProtocolError::InvalidProofOfKnowledge(participant));
    }
    Ok(())
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
