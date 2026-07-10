### Title
Malicious CKD Participant Can Submit Arbitrary Shares Without Verification, Corrupting the Coordinator's Derived Confidential Key — (File: `src/confidential_key_derivation/protocol.rs`)

---

### Summary

The `do_ckd_coordinator` function in the CKD protocol unconditionally sums `(big_y, big_c)` contributions received from every participant with no proof of correctness. Any single malicious participant can send arbitrary group elements in place of their honest share, causing the coordinator to assemble and return a corrupted `CKDOutput`. The honest coordinator and any downstream consumer of the output will silently accept a wrong confidential key.

---

### Finding Description

`do_ckd_coordinator` collects each participant's `(norm_big_y, norm_big_c)` pair and adds them directly into the running aggregate:

```rust
// src/confidential_key_derivation/protocol.rs  lines 50-55
for (_, participant_output) in
    recv_from_others::<CKDOutput>(&chan, waitpoint, &participants, me).await?
{
    norm_big_y += participant_output.big_y();
    norm_big_c += participant_output.big_c();
}
```

The honest computation performed by every participant in `compute_signature_share` establishes the invariant:

```
norm_big_y_i = λ_i · y_i · G
norm_big_c_i = λ_i · (x_i · H(pk ‖ app_id) + y_i · A)
```

where `x_i` is the participant's private signing share, `y_i` is a fresh random scalar, and `A` is the application public key. [1](#0-0) 

No zero-knowledge proof, commitment, or consistency check is required before the coordinator accepts and accumulates a participant's pair. A malicious participant's `do_ckd_participant` call simply serialises whatever bytes it chooses and sends them privately to the coordinator:

```rust
// src/confidential_key_derivation/protocol.rs  lines 17-33
fn do_ckd_participant(...) -> Result<CKDOutputOption, ProtocolError> {
    let (norm_big_y, norm_big_c) =
        compute_signature_share(participants, me, key_pair, app_id, app_pk, rng)?;
    let waitpoint = chan.next_waitpoint();
    chan.send_private(waitpoint, coordinator, &(norm_big_y, norm_big_c))?;
    Ok(None)
}
``` [2](#0-1) 

Nothing prevents the malicious participant from replacing the honest `(norm_big_y, norm_big_c)` with `(0, 0)` or any other arbitrary pair before calling `send_private`.

---

### Impact Explanation

The expected coordinator output satisfies:

```
C_total − Y_total · app_sk  =  msk · H(pk ‖ app_id)
```

where `msk = Σ λ_i · x_i` is the master secret key. If participant `j` sends `(0, 0)`, the coordinator's aggregate becomes:

```
Y_total  =  Σ_{i≠j} λ_i · y_i · G
C_total  =  (msk − λ_j · x_j) · H(pk ‖ app_id)  +  Σ_{i≠j} λ_i · y_i · A
```

Unmasking with `app_sk` yields `(msk − λ_j · x_j) · H(pk ‖ app_id)`, which is not the correct confidential key. The coordinator returns this wrong `CKDOutput` as a successful result; no error is raised. This is a **corruption of a CKD output so that honest parties accept an unusable cryptographic output**, matching the High-severity impact tier. [3](#0-2) 

---

### Likelihood Explanation

Any single participant in a CKD session can mount this attack. The attacker needs only to be a legitimate member of the `participants` list (which is the documented trust assumption for a malicious participant). No cryptographic break, key leakage, or external compromise is required. The attack is trivially reproducible on every CKD invocation.

---

### Recommendation

Require each participant to accompany their `(norm_big_y, norm_big_c)` with a zero-knowledge proof of correct formation. Concretely, each participant should prove in zero-knowledge that:

1. `norm_big_y = λ_i · y_i · G` for the same `y_i` used in step 2.
2. `norm_big_c = λ_i · x_i · H(pk ‖ app_id) + λ_i · y_i · A`, where `x_i` is consistent with the participant's public verification share `X_i = x_i · G2` established during DKG.

A standard Schnorr-style sigma protocol (or a Pedersen commitment + opening) over the BLS12-381 G1 group is sufficient. The coordinator must verify all proofs before accumulating any contribution; any failing proof should abort the protocol and identify the malicious participant.

---

### Proof of Concept

Setup: 3 participants `{A, B, C}`, coordinator = `C`, threshold = 2.

1. `A` and `C` run `compute_signature_share` honestly and produce correct `(norm_big_y_A, norm_big_c_A)` and `(norm_big_y_C, norm_big_c_C)`.
2. Malicious `B` ignores `compute_signature_share` and sends `(ElementG1::identity(), ElementG1::identity())` to coordinator `C` via `chan.send_private`.
3. Coordinator `C` accumulates:
   - `total_Y = norm_big_y_A + 0 + norm_big_y_C`
   - `total_C = norm_big_c_A + 0 + norm_big_c_C`
4. `do_ckd_coordinator` returns `Ok(Some(CKDOutput::new(total_Y, total_C)))` with no error.
5. The application calls `ckd_output.unmask(app_sk)` and obtains `(msk − λ_B · x_B) · H(pk ‖ app_id)` — a wrong confidential key — silently accepted as correct. [4](#0-3)

### Citations

**File:** src/confidential_key_derivation/protocol.rs (L17-33)
```rust
fn do_ckd_participant(
    mut chan: SharedChannel,
    participants: &ParticipantList,
    coordinator: Participant,
    me: Participant,
    key_pair: &KeygenOutput,
    app_id: &AppId,
    app_pk: PublicKey,
    rng: &mut impl CryptoRngCore,
) -> Result<CKDOutputOption, ProtocolError> {
    let (norm_big_y, norm_big_c) =
        compute_signature_share(participants, me, key_pair, app_id, app_pk, rng)?;
    let waitpoint = chan.next_waitpoint();
    chan.send_private(waitpoint, coordinator, &(norm_big_y, norm_big_c))?;

    Ok(None)
}
```

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
