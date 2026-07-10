### Title
Missing Lower-Bound Validation on `threshold` in FROST Signing and OT-ECDSA Signing Initialization — (`File: src/frost/mod.rs`, `src/ecdsa/ot_based_ecdsa/sign.rs`)

---

### Summary

`assert_sign_inputs` in `src/frost/mod.rs` (shared by EdDSA `sign_v1`/`sign_v2` and RedJubjub `sign`) and `sign` in `src/ecdsa/ot_based_ecdsa/sign.rs` accept any `threshold` value ≥ 0 without enforcing the protocol-required lower bound of 2. The DKG entry points (`assert_key_invariants`) correctly reject `threshold < 2`, but the signing entry points do not, creating an inconsistent parameter boundary that a caller can exploit to corrupt signing outputs.

---

### Finding Description

`assert_key_invariants` in `src/dkg.rs` enforces both bounds on `threshold`:

```rust
if threshold > participants.len() { ... }  // upper bound
if threshold < 2 { ... }                   // lower bound ← enforced here
``` [1](#0-0) 

`assert_sign_inputs` in `src/frost/mod.rs`, which gates every FROST signing call (`sign_v1`, `sign_v2`, RedJubjub `sign`), only enforces the upper bound:

```rust
if threshold.value() > participants.len() {
    return Err(InitializationError::ThresholdTooLarge { ... });
}
// ← no lower-bound check; threshold=0 or threshold=1 passes silently
``` [2](#0-1) 

The same gap exists in OT-based ECDSA `sign`:

```rust
if participants.len() < threshold {
    return Err(InitializationError::NotEnoughParticipantsForThreshold { ... });
}
// ← no check that threshold >= 2
``` [3](#0-2) 

`ReconstructionLowerBound` is a plain `usize` wrapper with no invariant enforced at construction time, so any value including 0 or 1 is accepted: [4](#0-3) 

When `threshold=1` reaches `construct_key_package`, it is passed directly as `min_signers` to the FROST `KeyPackage`:

```rust
u16::try_from(threshold.value())  // succeeds for 0 or 1
``` [5](#0-4) 

With `min_signers=1`, the FROST library's `round2::sign` check (`commitments.len() >= min_signers`) is trivially satisfied for any participant count ≥ 2. The signing package is then built and signature shares are computed using Lagrange coefficients derived from the actual signing set — but with a `KeyPackage` that declares the threshold as 1 instead of the true DKG threshold. When the coordinator calls `aggregate`, the FROST library verifies the final signature against the public key; because the Lagrange interpolation is inconsistent with the actual secret-sharing degree, the aggregated signature fails verification and `aggregate` returns an error, causing `ProtocolError::AssertionFailed`. Every honest participant has already committed nonces and sent their share — the session is unrecoverably aborted.

With `threshold=0`, `KeyPackage::new` receives `min_signers=0`, which may trigger a panic or undefined behavior inside the upstream FROST library.

---

### Impact Explanation

**High — Corruption of sign outputs so honest parties accept unusable cryptographic outputs.**

A caller (malicious coordinator or misconfigured library user) passes `threshold=1` (or `threshold=0`) to `sign_v1`, `sign_v2`, or OT-ECDSA `sign`. All honest participants expend nonces, send their signature shares, and wait for a result. The coordinator's `aggregate` call fails because the `KeyPackage` threshold is inconsistent with the actual DKG degree. The signing session is permanently aborted; the consumed presignature (for OT-ECDSA or FROST v2) cannot be reused. Repeated invocations permanently exhaust the presignature pool and deny signing to honest parties.

---

### Likelihood Explanation

**Medium.** The `threshold` parameter is caller-supplied with no type-level enforcement. Any library integrator who passes the wrong value — or a malicious coordinator who deliberately supplies `threshold=1` — triggers the bug. The DKG path correctly rejects this value, so the inconsistency is non-obvious and likely to be missed during integration.

---

### Recommendation

Add the same lower-bound guard to `assert_sign_inputs` and to `sign` in `src/ecdsa/ot_based_ecdsa/sign.rs` that already exists in `assert_key_invariants`:

```rust
// in assert_sign_inputs (src/frost/mod.rs)
if threshold.value() < 2 {
    return Err(InitializationError::ThresholdTooSmall {
        threshold: threshold.value(),
        min: 2,
    });
}

// in sign (src/ecdsa/ot_based_ecdsa/sign.rs)
if threshold < 2 {
    return Err(InitializationError::ThresholdTooSmall {
        threshold,
        min: 2,
    });
}
```

Alternatively, enforce the invariant at the `ReconstructionLowerBound` constructor level so it is impossible to construct a value below 2.

---

### Proof of Concept

1. Run DKG with 3 participants and `threshold=3` (accepted by `assert_key_invariants`).
2. Call `sign_v1` with the same 3 participants but `threshold=1`.
3. `assert_sign_inputs` passes: `1 <= 3` (upper-bound check only).
4. `construct_key_package` builds a `KeyPackage` with `min_signers=1`.
5. `round2::sign` succeeds (1 commitment ≤ 3 present).
6. Coordinator calls `aggregate`; the FROST library verifies the aggregated signature against the public key — verification fails because the Lagrange interpolation used degree-0 coefficients against degree-2 shares.
7. `ProtocolError::AssertionFailed("signature failed to verify")` is returned; the signing session is permanently aborted and the presignature is consumed. [6](#0-5) [7](#0-6) [8](#0-7) [9](#0-8)

### Citations

**File:** src/dkg.rs (L558-596)
```rust
pub fn assert_key_invariants(
    participants: &[Participant],
    me: Participant,
    threshold: impl Into<ReconstructionLowerBound>,
) -> Result<ParticipantList, InitializationError> {
    let threshold = usize::from(threshold.into());
    // need enough participants
    if participants.len() < 2 {
        return Err(InitializationError::NotEnoughParticipants {
            participants: participants.len(),
        });
    }

    // Step 1.1
    // validate threshold
    if threshold > participants.len() {
        return Err(InitializationError::ThresholdTooLarge {
            threshold,
            max: participants.len(),
        });
    }
    // Step 1.1
    if threshold < 2 {
        return Err(InitializationError::ThresholdTooSmall { threshold, min: 2 });
    }

    // ensure uniqueness of participants in the participant list
    let participants =
        ParticipantList::new(participants).ok_or(InitializationError::DuplicateParticipants)?;

    // ensure my presence in the participant list
    if !participants.contains(me) {
        return Err(InitializationError::MissingParticipant {
            role: "self",
            participant: me,
        });
    }
    Ok(participants)
}
```

**File:** src/frost/mod.rs (L120-160)
```rust
pub fn assert_sign_inputs(
    participants: &[Participant],
    threshold: impl Into<ReconstructionLowerBound>,
    me: Participant,
    coordinator: Participant,
) -> Result<ParticipantList, InitializationError> {
    let threshold = threshold.into();
    if participants.len() < 2 {
        return Err(InitializationError::NotEnoughParticipants {
            participants: participants.len(),
        });
    }
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

    // validate threshold
    if threshold.value() > participants.len() {
        return Err(InitializationError::ThresholdTooLarge {
            threshold: threshold.value(),
            max: participants.len(),
        });
    }

    // ensure the coordinator is a participant
    if !participants.contains(coordinator) {
        return Err(InitializationError::MissingParticipant {
            role: "coordinator",
            participant: coordinator,
        });
    }
    Ok(participants)
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

**File:** src/thresholds.rs (L9-24)
```rust
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, From, Into,
)]
pub struct ReconstructionLowerBound(usize);

// ----- MaxMalicious conversions -----
impl MaxMalicious {
    pub fn value(self) -> usize {
        self.0
    }
}

impl ReconstructionLowerBound {
    pub fn value(self) -> usize {
        self.0
    }
```

**File:** src/frost/eddsa/sign.rs (L37-62)
```rust
pub fn sign_v1(
    participants: &[Participant],
    threshold: impl Into<ReconstructionLowerBound>,
    me: Participant,
    coordinator: Participant,
    keygen_output: KeygenOutput,
    message: Vec<u8>,
    rng: impl CryptoRngCore + Send + 'static,
) -> Result<impl Protocol<Output = SignatureOption>, InitializationError> {
    let threshold = threshold.into();
    let participants = assert_sign_inputs(participants, threshold, me, coordinator)?;

    let comms = Comms::new();
    let chan = comms.shared_channel();
    let fut = fut_wrapper_v1(
        chan,
        participants,
        threshold,
        me,
        coordinator,
        keygen_output,
        message,
        rng,
    );
    Ok(make_protocol(comms, fut))
}
```

**File:** src/frost/eddsa/sign.rs (L360-368)
```rust
    Ok(KeyPackage::new(
        identifier,
        signing_share,
        verifying_share,
        *verifying_key,
        u16::try_from(threshold.value()).map_err(|_| {
            ProtocolError::Other("threshold cannot be converted to u16".to_string())
        })?,
    ))
```
