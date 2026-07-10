### Title
Missing `msg_hash == 0` Validation in OT-Based ECDSA `sign()` Allows Presign Secret Disclosure - (File: `src/ecdsa/ot_based_ecdsa/sign.rs`)

---

### Summary

The OT-based ECDSA `sign()` function accepts a zero `msg_hash` without rejection. When `msg_hash = 0`, the signing equation degenerates so that each participant's share reveals a scalar proportional to their secret nonce-key product `sigma_i`. The coordinator aggregates these into `sigma = k * x` (the product of the nonce and the master secret key). A malicious coordinator who then induces presignature reuse — which the OT-based protocol does not prevent at the code level — can recover the master secret key `x`. The robust ECDSA variant explicitly rejects `msg_hash == 0` for exactly this reason; the OT-based variant does not.

---

### Finding Description

In `src/ecdsa/ot_based_ecdsa/sign.rs`, the public entry point `sign()` performs several input validations (participant count, membership, threshold) but contains **no check for `msg_hash == 0`**:

```rust
// src/ecdsa/ot_based_ecdsa/sign.rs lines 22–76
pub fn sign(
    participants: &[Participant],
    coordinator: Participant,
    threshold: impl Into<ReconstructionLowerBound>,
    me: Participant,
    public_key: AffinePoint,
    presignature: RerandomizedPresignOutput,
    msg_hash: Scalar,          // ← zero is accepted without error
) -> Result<impl Protocol<Output = SignatureOption>, InitializationError> {
    // ... participant checks ...
    // NO msg_hash.is_zero() guard
    let ctx = Comms::new();
    let fut = fut_wrapper(..., msg_hash);
    Ok(make_protocol(ctx, fut))
}
``` [1](#0-0) 

The signing share is computed in `compute_signature_share()`:

```rust
// src/ecdsa/ot_based_ecdsa/sign.rs lines 139–159
fn compute_signature_share(..., msg_hash: Scalar) -> Result<Scalar, ProtocolError> {
    let lambda = participants.lagrange::<Secp256K1Sha256>(me)?;
    let k_i    = lambda * presignature.k;
    let sigma_i = lambda * presignature.sigma;
    let r = x_coordinate(&presignature.big_r);
    Ok(msg_hash * k_i + r * sigma_i)   // when msg_hash=0 → r * sigma_i
}
``` [2](#0-1) 

When `msg_hash = 0`, every participant sends `lambda_i * R_x * sigma_i` to the coordinator. The coordinator sums these to obtain:

```
s = R_x * Σ(lambda_i * sigma_i) = R_x * sigma
```

Since `R_x` is public, the coordinator immediately recovers `sigma = s / R_x`. In the OT-based presigning protocol, `sigma = k * x` — the product of the secret nonce `k` and the master secret key `x`.

By contrast, the robust ECDSA `sign()` function explicitly rejects this input:

```rust
// src/ecdsa/robust_ecdsa/sign.rs lines 91–95
if bool::from(msg_hash.is_zero()) {
    return Err(InitializationError::BadParameters(
        "msg_hash cannot be 0 to avoid potential split view attacks".to_string(),
    ));
}
``` [3](#0-2) 

The security documentation also explicitly warns against signing with `h = 0`: [4](#0-3) 

---

### Impact Explanation

**Impact: Critical — Extraction of the master secret key via presign secret disclosure.**

Once the coordinator holds `sigma = k * x`, a second signing session using the **same presignature** (presignature reuse, which the OT-based protocol does not prevent at the code level — `PresignOutput` is `Clone` and `Serialize`) with any `h ≠ 0` yields:

```
s1 = h * k + R_x * k * x = h * k + R_x * sigma
```

The coordinator then solves:

```
k = (s1 - R_x * sigma) / h
x = sigma / k
```

This is a complete extraction of the master secret key `x`. The `PresignOutput` struct is `Clone` and `Serialize/Deserialize`, and the OT-based scheme does not enforce the strict `N1 = N2 = 2t+1` constraint that the robust scheme uses to limit presignature reuse opportunities. [5](#0-4) 

---

### Likelihood Explanation

**Likelihood: Medium.**

The attacker must be the coordinator (a documented trust boundary in the protocol). The coordinator can:

1. Call `sign()` with `msg_hash = 0` — accepted without error.
2. Collect all participant shares, compute `sigma = s / R_x`.
3. Abort the session (participants may retain their `PresignOutput` for retry).
4. Initiate a second session with the same presignature and `h ≠ 0`.
5. Recover `x`.

The OT-based scheme allows `N2 ≥ t` participants (not the strict `2t+1` of robust ECDSA), giving the coordinator more flexibility to orchestrate overlapping sessions. The `PresignOutput` is cloneable and serializable, making reuse straightforward at the application layer. [6](#0-5) 

---

### Recommendation

Add a `msg_hash == 0` guard in `src/ecdsa/ot_based_ecdsa/sign.rs`, mirroring the check already present in the robust ECDSA variant:

```rust
if bool::from(msg_hash.is_zero()) {
    return Err(InitializationError::BadParameters(
        "msg_hash cannot be 0".to_string(),
    ));
}
```

This should be placed immediately after the participant-count and threshold checks, before the protocol future is constructed.

---

### Proof of Concept

**Setup:** 2 honest participants, 1 malicious coordinator, threshold = 2. Both participants hold a valid `PresignOutput` with `big_r = R`, `k = k_i`, `sigma = sigma_i` where `sigma = k * x`.

**Step 1 — Zero-hash session:**
Coordinator calls `sign(..., msg_hash = Scalar::ZERO)`. No error is returned. Each participant computes and sends `lambda_i * R_x * sigma_i`. Coordinator sums to get `s0 = R_x * sigma`. Coordinator computes `sigma = s0 / R_x`.

**Step 2 — Normal session (presignature reuse):**
Coordinator aborts step 1 before broadcasting the result. Participants, believing the session failed, retain their `PresignOutput`. Coordinator initiates a new session with the same presignature and `msg_hash = h ≠ 0`. Participants send `lambda_i * (h * k_i + R_x * sigma_i)`. Coordinator sums to get `s1 = h * k + R_x * sigma`.

**Step 3 — Key recovery:**
```
k = (s1 - R_x * sigma) / h
x = sigma / k
```

The master secret key `x` is fully recovered. The attack entry point is the missing zero-check at `src/ecdsa/ot_based_ecdsa/sign.rs` line 22–76, which the robust ECDSA variant guards against at `src/ecdsa/robust_ecdsa/sign.rs` lines 91–95. [1](#0-0) [3](#0-2)

### Citations

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

**File:** src/ecdsa/robust_ecdsa/sign.rs (L91-95)
```rust
    if bool::from(msg_hash.is_zero()) {
        return Err(InitializationError::BadParameters(
            "msg_hash cannot be 0 to avoid potential split view attacks".to_string(),
        ));
    }
```

**File:** docs/ecdsa/robust_ecdsa/signing.md (L179-181)
```markdown
4. **Do not sign with $h = 0$** (the zero message hash).
   This input enables a related algebraic split-view attack in the modified scheme when
   $N_1 > 2t + 1$.
```

**File:** src/ecdsa/ot_based_ecdsa/mod.rs (L40-49)
```rust
#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq, ZeroizeOnDrop)]
pub struct PresignOutput {
    /// The public nonce commitment.
    #[zeroize[skip]]
    pub big_r: AffinePoint,
    /// Our share of the nonce value.
    pub k: Scalar,
    /// Our share of the sigma value.
    pub sigma: Scalar,
}
```

**File:** src/ecdsa/ot_based_ecdsa/mod.rs (L54-63)
```rust
#[derive(Debug, Clone, Serialize, Deserialize, ZeroizeOnDrop)]
pub struct RerandomizedPresignOutput {
    /// The rerandomized public nonce commitment.
    #[zeroize[skip]]
    pub big_r: AffinePoint,
    /// Our rerandomized share of the nonce value.
    pub k: Scalar,
    /// Our rerandomized share of the sigma value.
    pub sigma: Scalar,
}
```
