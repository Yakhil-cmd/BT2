### Title
Missing `msg_hash` Zero-Value Check in OT-Based ECDSA `sign` — (`src/ecdsa/ot_based_ecdsa/sign.rs`)

---

### Summary

The OT-based ECDSA `sign` function accepts a `msg_hash: Scalar` parameter but performs no zero-value check on it. The sibling robust ECDSA `sign` function explicitly rejects a zero `msg_hash` with an `InitializationError`. This inconsistency allows a malicious coordinator or a front-end bug to drive honest participants into producing valid threshold signature shares over the zero message, yielding a fully valid ECDSA signature for attacker-chosen (zero) input.

---

### Finding Description

**Vulnerable function — no zero check:**

`src/ecdsa/ot_based_ecdsa/sign.rs`, lines 22–76: the public `sign` entry point accepts `msg_hash: Scalar` and validates participants, coordinator membership, and threshold size, but never checks whether `msg_hash` is zero. [1](#0-0) 

The docstring on the same function explicitly acknowledges the risk:

> **WARNING** You must absolutely hash an actual message before passing it to this function. Allowing the signing of arbitrary scalars *is* a security risk, and this function only tolerates this risk to allow for genericity. [2](#0-1) 

Despite the warning, no enforcement exists.

**Guarded function — zero check present:**

`src/ecdsa/robust_ecdsa/sign.rs`, lines 91–94: the robust ECDSA `sign` function explicitly rejects a zero `msg_hash`:

```rust
if bool::from(msg_hash.is_zero()) {
    return Err(InitializationError::BadParameters(
        "msg_hash cannot be 0 to avoid potential split view attacks".to_string(),
    ));
}
``` [3](#0-2) 

**Signature share computation with `msg_hash = 0`:**

In `compute_signature_share` (OT-based), the share is:

```rust
Ok(msg_hash * k_i + r * sigma_i)
``` [4](#0-3) 

With `msg_hash = 0` this collapses to `s_i = r * sigma_i`. After Lagrange aggregation the coordinator obtains `s = r · σ` where `σ = k⁻¹ · x` (inverse nonce times private key). This satisfies the standard ECDSA equation `s = k⁻¹(0 + r·x)` and is therefore a **fully valid signature** for the zero message.

---

### Impact Explanation

- **Unauthorized valid threshold signature**: the coordinator receives a cryptographically correct `(R, s)` pair for `msg_hash = 0`. This falls directly under the Critical impact class: *Unauthorized creation of a valid threshold signature for attacker-chosen inputs*.
- **Partial secret leakage**: the published signature satisfies `s/r = k⁻¹ · x`. Any party observing the signature learns the product of the inverse nonce and the private key. Combined with a second zero-message signature (different presignature), the ratio of nonces is exposed. If nonce material is ever recoverable (e.g., via a side channel or nonce reuse), the private key `x = s · k / r` is directly computable — matching the Critical impact class: *disclosure of nonce material or aggregate secret material*.
- The robust ECDSA variant explicitly documents and blocks this exact scenario, confirming the library authors consider it a real threat.

---

### Likelihood Explanation

- A malicious coordinator constructs a signing session and passes `msg_hash = 0` to each participant's `sign` call. Honest participants have no guard and will compute and send their shares.
- A front-end or integration bug (uninitialized variable, incorrect hash computation) can silently produce `msg_hash = 0`, exactly mirroring the exploit scenario in the reference report.
- The robust ECDSA path already blocks this, so the OT-based path is the only unguarded surface.

---

### Recommendation

Add the same zero-value guard present in the robust ECDSA `sign` function, immediately after the threshold check in `src/ecdsa/ot_based_ecdsa/sign.rs`:

```rust
if bool::from(msg_hash.is_zero()) {
    return Err(InitializationError::BadParameters(
        "msg_hash cannot be 0".to_string(),
    ));
}
``` [5](#0-4) 

---

### Proof of Concept

1. Obtain a valid `RerandomizedPresignOutput` for a set of participants via the normal presign flow.
2. Call `ot_based_ecdsa::sign(participants, coordinator, threshold, me, public_key, presignature, Scalar::ZERO)`.
3. Observe: no `InitializationError` is returned; the protocol runs to completion.
4. The coordinator collects all `s_i = r · sigma_i` shares, sums them (with Lagrange weights), and outputs a `Signature { big_r, s }`.
5. Verify with `sig.verify(&public_key, &Scalar::ZERO)` — verification passes, confirming a valid threshold ECDSA signature was produced for the zero message without any rejection at the API boundary. [6](#0-5) [7](#0-6)

### Citations

**File:** src/ecdsa/ot_based_ecdsa/sign.rs (L17-21)
```rust
/// The signature protocol, allowing us to use a presignature to sign a message.
///
/// **WARNING** You must absolutely hash an actual message before passing it to
/// this function. Allowing the signing of arbitrary scalars *is* a security risk,
/// and this function only tolerates this risk to allow for genericity.
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

**File:** src/ecdsa/ot_based_ecdsa/sign.rs (L97-136)
```rust
/// Performs signing from only the coordinator's perspective
async fn do_sign_coordinator(
    mut chan: SharedChannel,
    participants: ParticipantList,
    me: Participant,
    public_key: AffinePoint,
    presignature: RerandomizedPresignOutput,
    msg_hash: Scalar,
) -> Result<SignatureOption, ProtocolError> {
    // Round 1
    let s_i = compute_signature_share(&participants, me, &presignature, msg_hash)?;
    // Spec 1.4 is non-existent for a coordinator

    let wait0 = chan.next_waitpoint();
    // Receive sj
    // Spec 1.5
    let mut s = s_i;
    for (_, s_j) in recv_from_others::<Scalar>(&chan, wait0, &participants, me).await? {
        // Spec 1.6
        s += s_j;
    }

    // Normalize s
    // Spec 1.7
    s.conditional_assign(&(-s), s.is_high());

    let sig = Signature {
        big_r: presignature.big_r,
        s,
    };

    // Spec 1.8
    if !sig.verify(&public_key, &msg_hash) {
        return Err(ProtocolError::AssertionFailed(
            "signature failed to verify".to_string(),
        ));
    }

    Ok(Some(sig))
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
