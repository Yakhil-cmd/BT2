### Title
Missing Validation of Participant Contributions in CKD Protocol Allows Output Corruption — (File: `src/confidential_key_derivation/protocol.rs`)

### Summary

The Confidential Key Derivation (CKD) coordinator in `do_ckd_coordinator` blindly sums every participant's `(big_y, big_c)` contribution with no zero-knowledge proof or consistency check. Any single malicious participant can substitute arbitrary group elements, causing the coordinator to output a corrupted `CKDOutput` that honest parties accept as valid. This is the direct analog of the external report's pattern: a validation step that must be present is entirely absent, and the omission is reachable by any unprivileged protocol participant.

### Finding Description

`do_ckd_coordinator` in `src/confidential_key_derivation/protocol.rs` (lines 35–58) collects one `CKDOutput` from every other participant and unconditionally adds each contribution to the running aggregate:

```rust
for (_, participant_output) in
    recv_from_others::<CKDOutput>(&chan, waitpoint, &participants, me).await?
{
    norm_big_y += participant_output.big_y();
    norm_big_c += participant_output.big_c();
}
let ckd_output = CKDOutput::new(norm_big_y, norm_big_c);
``` [1](#0-0) 

Each honest participant `i` is supposed to compute:

- `big_y_i = y_i · G` (random blinding point)
- `big_c_i = x_i · H(pk ‖ app_id) + y_i · app_pk` (ElGamal encryption of the key share)
- `norm_big_y_i = λ_i · big_y_i`, `norm_big_c_i = λ_i · big_c_i` [2](#0-1) 

The coordinator then aggregates to obtain `C = x · H(pk ‖ app_id) + y · app_pk`, which unmasks to the confidential key `x · H(pk ‖ app_id)` when the application applies its secret key `app_sk`.

No proof is required or checked that a participant's `(norm_big_y, norm_big_c)` was derived from their actual signing share `x_i`. The library already implements a `dlogeq` proof (`src/crypto/proofs/dlogeq.rs`) that could prove exactly this relation, but it is not used here. [3](#0-2) 

**Attack path:**

1. Malicious participant `M` is a legitimate member of the CKD participant list.
2. Instead of computing `(norm_big_y_M, norm_big_c_M)` honestly, `M` sends `(norm_big_y_M + Δ_Y, norm_big_c_M + Δ_C)` for arbitrary chosen group elements `Δ_Y, Δ_C ∈ G₁`.
3. The coordinator sums all contributions including the poisoned pair.
4. The resulting `CKDOutput` is `(Y + Δ_Y, C + Δ_C)`.
5. When the TEE application unmasks: `(C + Δ_C) − app_sk · (Y + Δ_Y) = x · H(pk ‖ app_id) + Δ_C − app_sk · Δ_Y`, which is a corrupted key unless `Δ_C = app_sk · Δ_Y` (which requires knowing `app_sk`).
6. Honest parties receive and accept this corrupted `CKDOutput` with no error.

The CKD protocol has no threshold parameter — it requires all `n` participants to contribute correctly. [4](#0-3) 

### Impact Explanation

A single malicious participant can corrupt the `CKDOutput` accepted by the coordinator and all honest parties. The TEE application derives a wrong confidential key that is neither the intended `x · H(pk ‖ app_id)` nor a key the attacker controls (since `app_sk` is unknown to the attacker). The result is a permanently unusable CKD output for that invocation. This maps to:

> **High: Corruption of CKD outputs so honest parties accept inconsistent or unusable cryptographic outputs.**

### Likelihood Explanation

Any participant in a CKD session can execute this attack with no special privilege. The attacker only needs to be a valid member of the participant list (a normal protocol role). The attack requires sending two arbitrary group elements instead of the honest computation — trivially achievable by any library caller who controls their own protocol instance. There is no defense-in-depth check anywhere in the coordinator path.

### Recommendation

Add a zero-knowledge proof of correct contribution. Each participant should prove, using the existing `dlogeq` proof infrastructure (`src/crypto/proofs/dlogeq.rs`), that their `(norm_big_y, norm_big_c)` is consistent with their public verification share. Concretely, participant `i` should prove knowledge of `(x_i, y_i)` such that:

- `x_i · G₂ = vk_share_i` (their known verification share on G₂)
- `x_i · H(pk ‖ app_id) + y_i · app_pk = big_c_i`
- `y_i · G₁ = big_y_i`

The coordinator must verify this proof before accepting any contribution.

### Proof of Concept

```
Participants: [P1 (honest), P2 (honest), M (malicious)]
app_id = "Near App", app_pk = app_sk * G

Honest run:
  Each Pi sends (λ_i * y_i * G, λ_i * (x_i * H + y_i * app_pk))
  Coordinator sums → C = x * H + y * app_pk
  Unmask: C - app_sk * Y = x * H  ✓

Malicious run (M sends Δ_Y = random_point, Δ_C = random_point):
  Coordinator sums → C' = x * H + y * app_pk + Δ_C
                     Y' = y * G + Δ_Y
  Unmask: C' - app_sk * Y' = x * H + Δ_C - app_sk * Δ_Y  ✗ (wrong key)
  No error is raised; coordinator returns corrupted CKDOutput.
```

### Citations

**File:** src/confidential_key_derivation/protocol.rs (L50-57)
```rust
    for (_, participant_output) in
        recv_from_others::<CKDOutput>(&chan, waitpoint, &participants, me).await?
    {
        norm_big_y += participant_output.big_y();
        norm_big_c += participant_output.big_c();
    }
    let ckd_output = CKDOutput::new(norm_big_y, norm_big_c);
    Ok(Some(ckd_output))
```

**File:** src/confidential_key_derivation/protocol.rs (L66-117)
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

    let comms = Comms::new();
    let chan = comms.shared_channel();

    let fut = run_ckd_protocol(
        chan,
        coordinator,
        me,
        participants,
        key_pair,
        app_id.into(),
        app_pk,
        rng,
    );
    Ok(make_protocol(comms, fut))
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

**File:** src/crypto/proofs/dlogeq.rs (L136-164)
```rust
/// Verify that a proof attesting to the validity of some statement.
///
/// We use a transcript in order to verify the Fiat-Shamir transformation.
pub fn verify<C: Ciphersuite>(
    transcript: &mut Transcript,
    statement: Statement<'_, C>,
    proof: &Proof<C>,
) -> Result<bool, ProtocolError>
where
    Element<C>: ConstantTimeEq,
{
    if statement.generator1.ct_eq(&C::Group::identity()).into() {
        return Err(ProtocolError::IdentityElement);
    }

    transcript.message(NEAR_DLOGEQ_STATEMENT_LABEL, &statement.encode()?);

    let (phi0, phi1) = statement.phi(&proof.s.0);
    let big_k0 = phi0 - *statement.public0 * proof.e.0;
    let big_k1 = phi1 - *statement.public1 * proof.e.0;

    let enc = encode_two_points::<C>(&big_k0, &big_k1)?;

    transcript.message(NEAR_DLOGEQ_COMMITMENT_LABEL, &enc);
    let mut rng = transcript.challenge_then_build_rng(NEAR_DLOGEQ_CHALLENGE_LABEL);
    let e = frost_core::random_nonzero::<C, _>(&mut rng);

    Ok(e == proof.e.0)
}
```
