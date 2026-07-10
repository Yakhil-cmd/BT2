### Title
Missing Zero `msg_hash` Validation in OT-Based ECDSA Sign Allows Presign Secret Share Disclosure — (`src/ecdsa/ot_based_ecdsa/sign.rs`)

---

### Summary

The OT-based ECDSA `sign` function accepts `msg_hash = 0` without rejection. The robust ECDSA `sign` function explicitly rejects zero message hashes to prevent algebraic attacks. When `msg_hash = 0`, the signature share formula collapses to `s_i = R'_x * sigma_i'`, allowing the coordinator to divide out the public `R'_x` and recover each participant's individual rerandomized presign secret share `sigma_i'`.

---

### Finding Description

In `src/ecdsa/robust_ecdsa/sign.rs`, the `sign` function enforces:

```rust
if bool::from(msg_hash.is_zero()) {
    return Err(InitializationError::BadParameters(
        "msg_hash cannot be 0 to avoid potential split view attacks".to_string(),
    ));
}
``` [1](#0-0) 

The OT-based ECDSA `sign` function in `src/ecdsa/ot_based_ecdsa/sign.rs` performs no such check. It accepts any `msg_hash: Scalar`, including zero, and proceeds directly to protocol execution: [2](#0-1) 

The `compute_signature_share` function computes each participant's share as:

```rust
let r = x_coordinate(&presignature.big_r);
Ok(msg_hash * k_i + r * sigma_i)
``` [3](#0-2) 

When `msg_hash = 0`, this reduces to:

```
s_i = 0 * k_i + R'_x * sigma_i
    = R'_x * sigma_i
```

Since `R'_x = x_coordinate(&presignature.big_r)` is a public value known to all parties, the coordinator can compute:

```
sigma_i = s_i / (R'_x * lambda_i)
```

for every participant `i`, recovering each participant's individual rerandomized presign secret share `presignature.sigma`.

The security documentation for the robust ECDSA scheme explicitly documents this concern:

> "Do not sign with h = 0. This input enables a related algebraic split-view attack in the modified scheme." [4](#0-3) 

The OT-based ECDSA scheme has no analogous guard.

---

### Impact Explanation

**Critical — Disclosure of presign secrets.**

Each participant's `presignature.sigma` is a rerandomized share of `sigma' = (k·x + ε·k)·δ⁻¹`, where `x` is the long-term private key scalar, `k` is the one-time nonce, `ε` is the public tweak, and `δ` is the public HKDF-derived rerandomization factor. These are presign secrets that are never supposed to be individually observable by the coordinator.

Under normal operation (`h ≠ 0`), the coordinator receives `s_i = h·k_i + R'_x·sigma_i`, which is a linear combination of two secrets — the coordinator cannot separate `k_i` from `sigma_i`. With `h = 0`, the `k_i` term vanishes entirely, and `sigma_i` is directly exposed.

If a malicious coordinator additionally induces presignature reuse across two sessions with `h = 0` and `h ≠ 0` (or two sessions with `h = 0` and different tweaks `ε`), they can solve for both `k_i` and `sigma_i` individually, enabling full private key reconstruction: `x = sigma / k`.

---

### Likelihood Explanation

The `sign` function is a public API callable by any library user or coordinator. Passing `Scalar::ZERO` as `msg_hash` requires no special privilege — it is a single-line change at the call site. A malicious coordinator controlling the signing session setup can supply `msg_hash = 0` to all participants. Each participant's protocol instance will proceed normally, compute `s_i = R'_x * sigma_i`, and send it to the coordinator. No participant-side check exists to detect or reject this condition.

---

### Recommendation

Add the same zero-hash guard present in the robust ECDSA `sign` function:

```rust
// In src/ecdsa/ot_based_ecdsa/sign.rs, inside `sign()`, before spawning the protocol:
if bool::from(msg_hash.is_zero()) {
    return Err(InitializationError::BadParameters(
        "msg_hash cannot be

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

**File:** src/ecdsa/ot_based_ecdsa/sign.rs (L155-158)
```rust
    // Compute si = h * ki + Rx * sigmai
    // Spec 1.3
    let r = x_coordinate(&presignature.big_r);
    Ok(msg_hash * k_i + r * sigma_i)
```

**File:** docs/ecdsa/robust_ecdsa/signing.md (L179-181)
```markdown
4. **Do not sign with $h = 0$** (the zero message hash).
   This input enables a related algebraic split-view attack in the modified scheme when
   $N_1 > 2t + 1$.
```
