### Title
Missing Proof of Correct Computation in CKD Protocol Allows Malicious Participant to Corrupt Derived Confidential Key — (File: `src/confidential_key_derivation/protocol.rs`)

---

### Summary

The CKD coordinator blindly aggregates each participant's `(norm_big_y, norm_big_c)` contribution without any cryptographic proof that the participant used their actual secret key share. A single malicious participant can send arbitrary group elements, causing the coordinator to output a corrupted CKD result that honest parties accept as valid.

---

### Finding Description

In `do_ckd_coordinator` (`src/confidential_key_derivation/protocol.rs`, lines 35–58), the coordinator collects each participant's output and sums them unconditionally:

```rust
for (_, participant_output) in
    recv_from_others::<CKDOutput>(&chan, waitpoint, &participants, me).await?
{
    norm_big_y += participant_output.big_y();
    norm_big_c += participant_output.big_c();
}
```

Each honest participant is supposed to compute, in `compute_signature_share` (lines 148–182):

```
big_s  = x_i · H(pk ‖ app_id)      // secret share times hash point
big_c  = big_s + y · app_pk         // masked with app public key
big_y  = y · G                      // blinding commitment
```

then normalize both with their Lagrange coefficient and send `(norm_big_y, norm_big_c)` to the coordinator.

The coordinator has **no mechanism to verify** that:

1. `big_y` is a valid commitment to the blinding scalar `y` (i.e., `big_y = y·G`).
2. `big_c` was formed using the participant's actual secret share `x_i` consistent with their public key share.
3. The same `y` was used in both `big_y` and `big_c`.

There is no zero-knowledge proof of correct computation attached to the contribution. The codebase already contains the necessary ZKP primitives (`src/crypto/proofs/dlogeq.rs`) for proving discrete-log equality across two generators, which is exactly what would be needed here, but they are not applied in the CKD path.

The analog to the external report is direct: just as `validateTransaction` accepted an attacker-supplied `unshieldPreimage` without checking it was correct, `do_ckd_coordinator` accepts attacker-supplied `(big_y, big_c)` without checking they were honestly computed.

---

### Impact Explanation

**High — Corruption of CKD output so honest parties accept an unusable or wrong derived key.**

The final CKD output is:

```
Y = Σ λ_i · y_i · G
C = Σ λ_i · (x_i · H + y_i · A)
```

The TEE application unmasks with its secret scalar `a`:

```
C − a·Y  =  msk · H(pk ‖ app_id)   (the confidential derived key)
```

A malicious participant substitutes arbitrary `(big_y*, big_c*)` for their honest contribution. The coordinator sums these in, producing:

```
Y'  = Y_honest + big_y*
C'  = C_honest + big_c*
```

The unmask result becomes `msk·H + (big_c* − a·big_y*)`, which is a wrong key. Because the coordinator performs no verification, it outputs this corrupted `CKDOutput` as if it were valid. Every honest party that relies on the derived key receives a wrong, unusable secret. This satisfies the allowed impact: *"Corruption of … CKD outputs so honest parties accept … unusable cryptographic outputs."*

---

### Likelihood Explanation

**Medium.** Any single participant in the CKD protocol can trigger this. The protocol collects contributions from **all** participants (not a threshold subset), so even one malicious participant out of N is sufficient. No special privilege beyond being a registered participant is required. The attacker simply sends arbitrary `ElementG1` values instead of their honest computation.

---

### Recommendation

Require each participant to attach a zero-knowledge proof of correct computation alongside their `(norm_big_y, norm_big_c)` contribution. Concretely, the participant should prove:

- Knowledge of scalar `y` such that `big_y = y·G` (dlog proof).
- Knowledge of scalar `y` such that `big_c − x_i·H = y·app_pk` (dlog equality proof across generators `G` and `app_pk`), binding the blinding term to the same `y`.
- That `x_i` is consistent with the participant's public key share (already committed during DKG).

The `dlogeq::prove` / `dlogeq::verify` functions in `src/crypto/proofs/dlogeq.rs` provide the necessary primitive. The coordinator should verify each proof before accumulating the contribution, and reject (and identify) any participant whose proof fails.

---

### Proof of Concept

1. Run a CKD session with N honest participants and one malicious participant P*.
2. P* intercepts the protocol at the point where it would call `compute_signature_share` and instead constructs an arbitrary `CKDOutput { big_y: ElementG1::generator(), big_c: ElementG1::generator() }`.
3. P* sends this to the coordinator via `chan.send_private(waitpoint, coordinator, &(big_y, big_c))`.
4. The coordinator's loop in `do_ckd_coordinator` (lines 50–55) adds these values to the running sum without any check.
5. The final `CKDOutput` returned by the coordinator is `(Y_honest + G, C_honest + G)`.
6. When the TEE application calls `ckd_output.unmask(app_sk)`, it computes `(C_honest + G) − app_sk·(Y_honest + G)`, which equals `msk·H + G(1 − app_sk)` — a wrong key — instead of the correct `msk·H(pk ‖ app_id)`.
7. The honest coordinator and all honest participants have accepted and acted on a corrupted CKD output with no error raised. [1](#0-0) [2](#0-1) [3](#0-2)

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
