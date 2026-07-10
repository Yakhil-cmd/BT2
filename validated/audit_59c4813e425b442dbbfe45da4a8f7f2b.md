Looking at the CKD protocol in `src/confidential_key_derivation/protocol.rs`, I can identify a valid analog.

---

### Title
Unverified Participant Shares in CKD Coordinator Allow Malicious Participant to Corrupt Derived Confidential Key - (File: `src/confidential_key_derivation/protocol.rs`)

### Summary
The CKD coordinator aggregates `(big_y, big_c)` shares from participants without any cryptographic verification that those values are correctly formed relative to each participant's committed public key share. A single malicious participant can send arbitrary group elements, causing the coordinator to produce a corrupted `CKDOutput` that decrypts to a wrong key, permanently denying the CKD service for honest parties.

### Finding Description

In `do_ckd_coordinator`, the coordinator receives each participant's `(norm_big_y, norm_big_c)` pair and blindly sums them:

```rust
for (_, participant_output) in
    recv_from_others::<CKDOutput>(&chan, waitpoint, &participants, me).await?
{
    norm_big_y += participant_output.big_y();
    norm_big_c += participant_output.big_c();
}
``` [1](#0-0) 

Each participant is supposed to compute and send:

```
norm_big_y = λ_i · y_i · G₁
norm_big_c = λ_i · (x_i · H(pk ∥ app_id) + y_i · app_pk)
``` [2](#0-1) 

The coordinator performs **no verification** that the received `(big_y, big_c)` values are consistent with the participant's committed public key share `pk_i = x_i · G₂` from DKG. In BLS12-381, such a check is possible via a pairing equation:

```
e(big_c, G₂) == e(H(pk ∥ app_id), pk_i) · e(app_pk, big_y)
```

This check is entirely absent. The coordinator uses the raw, unverified "spot" values from each participant's message, directly analogous to reading `slot0()` spot price without TWAP verification.

The participant-side function `do_ckd_participant` is non-async and one-way — it sends `(norm_big_y, norm_big_c)` to the coordinator and returns `None` immediately, with no round-trip that would allow detection: [3](#0-2) 

### Impact Explanation

**Impact: High** — Corruption of CKD outputs so honest parties accept unusable cryptographic outputs.

A malicious participant sends `(big_y + Δ_y, big_c + Δ_c)` for arbitrary group elements `Δ_y, Δ_c ∈ G₁`. The coordinator computes:

```
Y' = Y + Δ_y
C' = C + Δ_c
```

When the application unmasks with `app_sk`:

```
C' − app_sk · Y' = msk · H(pk ∥ app_id) + Δ_c − app_sk · Δ_y
```

Unless `Δ_c = app_sk · Δ_y` (which requires knowing `app_sk`, a secret the malicious participant does not hold), the derived confidential key is permanently wrong. The honest application receives a `CKDOutput` that appears structurally valid but decrypts to garbage, with no error signal. There is no retry mechanism — the protocol terminates with a corrupted result.

### Likelihood Explanation

**Likelihood: High** — Any single malicious participant in the protocol can trigger this. The attack requires only that the participant deviate from the protocol by sending arbitrary G₁ elements instead of correctly computed shares. No special capability, leaked key, or external assumption is needed. The coordinator has no mechanism to detect or attribute the deviation.

### Recommendation

Add a pairing-based consistency check in `do_ckd_coordinator` for each received `(big_y_i, big_c_i)` against the participant's known public key share `pk_i` (available from the DKG output):

```
e(big_c_i, G₂) == e(H(pk ∥ app_id), pk_i) · e(app_pk, big_y_i)
```

This binds each participant's CKD contribution to their committed DKG public key share, exactly as TWAP binds a price to a time-averaged committed history rather than a manipulatable spot reading. Participants whose shares fail this check should be identified and excluded, and the protocol should abort or retry without them.

### Proof of Concept

1. Honest participants hold shares `x_i` with public key shares `pk_i = x_i · G₂` from DKG.
2. Malicious participant `j` computes the correct `(norm_big_y_j, norm_big_c_j)` but instead sends `(norm_big_y_j + Δ_y, norm_big_c_j + Δ_c)` for any non-zero `Δ_y, Δ_c ∈ G₁`.
3. The coordinator at `do_ckd_coordinator` receives these values and sums them without verification. [4](#0-3) 
4. The resulting `CKDOutput` satisfies `C' − app_sk · Y' = msk · H(pk ∥ app_id) + (Δ_c − app_sk · Δ_y) ≠ msk · H(pk ∥ app_id)`.
5. The application's call to `ckd_output.unmask(app_sk)` returns a wrong key with no error, permanently corrupting the CKD result for all honest parties in this session.

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

**File:** src/confidential_key_derivation/protocol.rs (L44-57)
```rust
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
