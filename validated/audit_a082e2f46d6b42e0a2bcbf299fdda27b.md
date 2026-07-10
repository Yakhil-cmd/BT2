### Title
Missing `msg_hash != 0` Validation in OT-Based ECDSA `sign()` Allows Presign Secret Disclosure to Coordinator - (File: `src/ecdsa/ot_based_ecdsa/sign.rs`)

---

### Summary

The OT-based ECDSA `sign()` entry-point function accepts a zero `msg_hash` without error. The robust ECDSA `sign()` function in the same repository explicitly rejects `msg_hash == 0` and documents it as a split-view attack prevention measure. When `msg_hash = 0`, each participant's signature share degenerates to `s_j = r * σ_j`, which the coordinator can invert to recover each participant's secret nonce share `σ_j`, and from threshold-many shares reconstruct the presign secret `σ = k · x`.

---

### Finding Description

In `src/ecdsa/robust_ecdsa/sign.rs`, the `sign()` function contains an explicit guard:

```rust
if bool::from(msg_hash.is_zero()) {
    return Err(InitializationError::BadParameters(
        "msg_hash cannot be 0 to avoid potential split view attacks".to_string(),
    ));
}
``` [1](#0-0) 

The analogous entry-point in `src/ecdsa/ot_based_ecdsa/sign.rs` performs no such check. Its validation block only covers participant count, duplicates, self-membership, coordinator membership, and threshold size — `msg_hash` is accepted unconditionally:

```rust
pub fn sign(
    participants: &[Participant],
    coordinator: Participant,
    threshold: impl Into<ReconstructionLowerBound>,
    me: Participant,
    public_key: AffinePoint,
    presignature: RerandomizedPresignOutput,
    msg_hash: Scalar,          // ← never checked for zero
) -> Result<impl Protocol<Output = SignatureOption>, InitializationError> {
``` [2](#0-1) 

The per-participant signature share computation is:

```rust
fn compute_signature_share(...) -> Result<Scalar, ProtocolError> {
    let lambda = participants.lagrange::<Secp256K1Sha256>(me)?;
    let k_i    = lambda * presignature.k;
    let sigma_i = lambda * presignature.sigma;
    let r = x_coordinate(&presignature.big_r);
    Ok(msg_hash * k_i + r * sigma_i)   // ← if msg_hash == 0, reduces to r * sigma_i
}
``` [3](#0-2) 

When `msg_hash = 0`, every participant j sends `s_j = r · λ_j · σ_j` to the coordinator. The coordinator collects all shares:

```rust
for (_, s_j) in recv_from_others::<Scalar>(&chan, wait0, &participants, me).await? {
    s += s_j;
}
``` [4](#0-3) 

Because `r` and `λ_j` are both public, the coordinator can compute `σ_j = s_j / (r · λ_j)` for every participant j. With threshold-many such shares the coordinator performs Lagrange interpolation to reconstruct the full presign secret `σ = k · x` (the product of the ephemeral nonce and the long-term private key).

---

### Impact Explanation

Reconstructing `σ = k · x` constitutes disclosure of presign secret material. This falls under the Critical allowed impact: *"Extraction, reconstruction, or disclosure of … presign secrets, nonce material."*

If the coordinator additionally obtains `k` (e.g., from a second zero-hash signing session targeting the nonce shares, or from a presignature reuse scenario), they can divide to recover the long-term private key `x = σ / k`, escalating to full key extraction.

---

### Likelihood Explanation

A malicious coordinator controls which message hash is presented to participants for signing. Nothing in the library prevents the coordinator from instructing all participants to call `sign()` with `msg_hash = 0`. Each participant's local call to `sign()` succeeds without error because the missing guard is the only place this could be caught. The attack requires no cryptographic break, no leaked keys, and no external dependency — only the ability to choose the message, which is the coordinator's normal role.

---

### Recommendation

Add the same guard that already exists in the robust ECDSA `sign()` function, immediately after the threshold check in `src/ecdsa/ot_based_ecdsa/sign.rs`:

```rust
if bool::from(msg_hash.is_zero()) {
    return Err(InitializationError::BadParameters(
        "msg_hash cannot be 0: reveals presign secret shares to the coordinator".to_string(),
    ));
}
```

This mirrors the existing check in `src/ecdsa/robust_ecdsa/sign.rs` at lines 91–95 and closes the asymmetry between the two signing implementations. [1](#0-0) 

---

### Proof of Concept

1. Run a normal OT-based ECDSA keygen and presign to obtain `PresignOutput { big_r, k, sigma }` for each participant.
2. Call `sign()` on every participant with `msg_hash = Scalar::ZERO`.
3. Each participant computes and sends `s_j = r · λ_j · σ_j` (the `k_i` term vanishes).
4. The coordinator receives all `s_j`. For each j, compute `σ_j = s_j · (r · λ_j)^{-1}` — both `r = x_coordinate(big_r)` and `λ_j = participants.lagrange(j)` are public.
5. Lagrange-interpolate the recovered `σ_j` values at zero to obtain `σ = k · x`.
6. Verify: `σ · G = k · x · G = k · public_key`, confirming the presign secret has been reconstructed.

### Citations

**File:** src/ecdsa/robust_ecdsa/sign.rs (L91-95)
```rust
    if bool::from(msg_hash.is_zero()) {
        return Err(InitializationError::BadParameters(
            "msg_hash cannot be 0 to avoid potential split view attacks".to_string(),
        ));
    }
```

**File:** src/ecdsa/ot_based_ecdsa/sign.rs (L22-76)
```rust
pub fn sign(
    participants: &[Participant],
    coordinator: Participant,
    threshold: impl Into<ReconstructionLowerBound>,
    me: Participant,
    public_key: AffinePoint,
    presignature: RerandomizedPresignOutput,
    msg_hash: Scalar,
) -> Result<impl Protocol<Output = SignatureOption>, InitializationError> {
    let threshold = usize::from(threshold.into());
    if participants.len() < 2 {
        return Err(InitializationError::NotEnoughParticipants {
            participants: participants.len(),
        });
    }

    let participants =
        ParticipantList::new(participants).ok_or(InitializationError::DuplicateParticipants)?;

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

    // ensure number of participants during the signing phase is >= threshold
    if participants.len() < threshold {
        return Err(InitializationError::NotEnoughParticipantsForThreshold {
            threshold,
            participants: participants.len(),
        });
    }

    let ctx = Comms::new();
    let fut = fut_wrapper(
        ctx.shared_channel(),
        participants,
        coordinator,
        me,
        public_key,
        presignature,
        msg_hash,
    );
    Ok(make_protocol(ctx, fut))
}
```

**File:** src/ecdsa/ot_based_ecdsa/sign.rs (L114-117)
```rust
    for (_, s_j) in recv_from_others::<Scalar>(&chan, wait0, &participants, me).await? {
        // Spec 1.6
        s += s_j;
    }
```

**File:** src/ecdsa/ot_based_ecdsa/sign.rs (L139-159)
```rust
fn compute_signature_share(
    participants: &ParticipantList,
    me: Participant,
    presignature: &RerandomizedPresignOutput,
    msg_hash: Scalar,
) -> Result<Scalar, ProtocolError> {
    // Round 1
    // Linearize ki
    // Spec 1.1
    let lambda = participants.lagrange::<Secp256K1Sha256>(me)?;
    let k_i = lambda * presignature.k;

    // Linearize sigmai
    // Spec 1.2
    let sigma_i = lambda * presignature.sigma;

    // Compute si = h * ki + Rx * sigmai
    // Spec 1.3
    let r = x_coordinate(&presignature.big_r);
    Ok(msg_hash * k_i + r * sigma_i)
}
```
