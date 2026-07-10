### Title
Missing Zero `msg_hash` Check in OT-Based ECDSA `sign` Allows Signing with Zero Message Hash — (File: `src/ecdsa/ot_based_ecdsa/sign.rs`)

---

### Summary

The OT-based ECDSA `sign` function accepts `msg_hash = 0` without any validation, while the sibling Robust ECDSA `sign` function explicitly rejects it. This missing zero-value check is the direct analog of the reported "Transfer of 0 funds" class: a critical guard present in one code path is absent in the parallel code path. Signing with `h = 0` produces a structurally valid ECDSA signature that algebraically reveals the product `k · x` (nonce × secret key). Combined with presignature reuse — a realistic failure mode — this enables full secret key extraction.

---

### Finding Description

`src/ecdsa/robust_ecdsa/sign.rs` explicitly guards against a zero message hash:

```rust
if bool::from(msg_hash.is_zero()) {
    return Err(InitializationError::BadParameters(
        "msg_hash cannot be 0 to avoid potential split view attacks".to_string(),
    ));
}
``` [1](#0-0) 

The parallel OT-based ECDSA entry point `src/ecdsa/ot_based_ecdsa/sign.rs` performs no such check. Its entire input-validation block is:

```rust
if participants.len() < 2 { ... }
// duplicate check, self-presence, coordinator-presence, threshold count
// — no msg_hash.is_zero() guard anywhere
``` [2](#0-1) 

When `msg_hash = 0`, the per-participant share computation reduces to:

```
s_i = h · k_i + R_x · sigma_i
    = 0  · k_i + R_x · sigma_i
    = R_x · sigma_i
``` [3](#0-2) 

After Lagrange interpolation the coordinator aggregates `s = R_x · sigma`, where `sigma = k · x` (nonce × secret key). The coordinator's final verification:

```rust
if !sig.verify(&public_key, &msg_hash) {
    return Err(...);
}
``` [4](#0-3) 

…passes, because `(R, R_x · k · x)` is a mathematically valid ECDSA signature for `h = 0`. The protocol completes successfully and returns the signature.

---

### Impact Explanation

**Algebraic leakage.** The returned signature `(R, s)` with `s = R_x · k · x` directly encodes the product `k · x`. Because `R_x` is public, any observer learns `k · x`.

**Secret key extraction via presignature reuse.** If the same presignature `(R, k, sigma)` is used in two sessions — a realistic failure mode due to bugs, crashes, or a malicious coordinator — and one session uses `h = 0`:

```
Session 1 (h = 0):  s₁ = k · R_x · x
Session 2 (h ≠ 0):  s₂ = k · (h + R_x · x) = k·h + s₁
```

Solving: `k = (s₂ − s₁) / h` and `x = s₁ · h / (R_x · (s₂ − s₁))`.

The full aggregate secret key `x` is recovered from two public signatures. This falls squarely under **Critical: Extraction, reconstruction, or disclosure of aggregate secret material**.

The robust ECDSA README explicitly documents this danger and enforces the guard:

> "Additionally, `msg_hash == 0` is rejected to prevent a related-key split-view attack." [5](#0-4) 

The OT-based scheme's documentation and code contain no equivalent restriction.

---

### Likelihood Explanation

**Attacker-controlled entry path:** `msg_hash` is a raw `Scalar` supplied directly by the caller. Any participant acting as coordinator, or any application layer that constructs the signing call, can pass `Scalar::ZERO`. No cryptographic capability is required.

**Presignature reuse:** The library documents "never reuse a presignature" as a security invariant, but enforces it only by convention. A malicious coordinator can trivially reuse a presignature across two signing sessions — one with `h = 0` and one with `h ≠ 0` — to execute the extraction. The robust ECDSA scheme mitigates this by enforcing `N₁ = N₂ = 2t+1` and rejecting `h = 0`; the OT-based scheme enforces neither.

---

### Recommendation

Add the same guard present in the robust ECDSA `sign` function to `src/ecdsa/ot_based_ecdsa/sign.rs`, immediately after the participant-count checks:

```rust
if bool::from(msg_hash.is_zero()) {
    return Err(InitializationError::BadParameters(
        "msg_hash cannot be 0: signing with a zero hash leaks nonce·key material".to_string(),
    ));
}
```

This mirrors the existing defense in `src/ecdsa/robust_ecdsa/sign.rs` lines 91–95 and closes the asymmetry between the two signing paths.

---

### Proof of Concept

1. Run the OT-based ECDSA pipeline to obtain a `RerandomizedPresignOutput` for participants `[P1, P2]` with threshold 2.
2. Call `ot_based_ecdsa::sign::sign(participants, coordinator, threshold, me, pk, presignature.clone(), Scalar::ZERO)` — this succeeds and returns signature `(R, s₁)` where `s₁ = R_x · k · x`.
3. Call `ot_based_ecdsa::sign::sign(participants, coordinator, threshold, me, pk, presignature, h)` for any nonzero `h` — this returns `(R, s₂)` where `s₂ = k·h + s₁`.
4. Compute `k = (s₂ − s₁) / h` and `x = s₁ · h / (R_x · (s₂ − s₁))`.
5. Verify `x · G == public_key`. The secret key is fully recovered.

The `sign` function's lack of a `msg_hash.is_zero()` guard — present in `src/ecdsa/robust_ecdsa/sign.rs` but absent in `src/ecdsa/ot_based_ecdsa/sign.rs` — is the sole necessary vulnerable step. [2](#0-1) [1](#0-0)

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

**File:** src/ecdsa/ot_based_ecdsa/sign.rs (L129-133)
```rust
    if !sig.verify(&public_key, &msg_hash) {
        return Err(ProtocolError::AssertionFailed(
            "signature failed to verify".to_string(),
        ));
    }
```

**File:** src/ecdsa/ot_based_ecdsa/sign.rs (L155-158)
```rust
    // Compute si = h * ki + Rx * sigmai
    // Spec 1.3
    let r = x_coordinate(&presignature.big_r);
    Ok(msg_hash * k_i + r * sigma_i)
```

**File:** src/ecdsa/robust_ecdsa/README.md (L34-34)
```markdown
Additionally, `msg_hash == 0` is rejected to prevent a related-key split-view attack.
```
