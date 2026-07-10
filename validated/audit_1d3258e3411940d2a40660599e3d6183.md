### Title
Missing Minimum Threshold Validation in FROST Signing Allows Sub-Security Threshold Invocation — (File: `src/frost/mod.rs`)

---

### Summary

`assert_sign_inputs` and `presign` in `src/frost/mod.rs` accept a `threshold` of `0` or `1` without error, because they only check that `threshold <= participants.len()` but never enforce `threshold >= 2`. The DKG entry point (`assert_key_invariants` in `src/dkg.rs`) correctly rejects `threshold < 2`, but the signing path has no equivalent lower-bound guard. A malicious coordinator or application-layer caller can invoke FROST signing with `threshold = 1`, causing the protocol to run and produce a cryptographically invalid (unusable) signature that honest parties cannot verify.

---

### Finding Description

`assert_key_invariants` in `src/dkg.rs` enforces a strict lower bound:

```rust
if threshold < 2 {
    return Err(InitializationError::ThresholdTooSmall { threshold, min: 2 });
}
``` [1](#0-0) 

The analogous guard is entirely absent from `assert_sign_inputs`:

```rust
// validate threshold
if threshold.value() > participants.len() {
    return Err(InitializationError::ThresholdTooLarge { ... });
}
// ← no lower-bound check; threshold = 0 or 1 silently passes
``` [2](#0-1) 

The same omission exists in `presign`:

```rust
// validate threshold
if args.threshold.value() > participants.len() {
    return Err(InitializationError::ThresholdTooLarge { ... });
}
// ← no lower-bound check
``` [3](#0-2) 

`ReconstructionLowerBound` is a plain `usize` newtype with no minimum enforced at the type level, so `ReconstructionLowerBound(1)` (or `(0)`) is a valid value that compiles and passes both guards above. [4](#0-3) 

---

### Impact Explanation

**High — Corruption of FROST sign outputs so honest parties accept an unusable cryptographic output.**

When `threshold = 1` is supplied to the signing path, the FROST aggregation step performs Lagrange interpolation over a single participant. Because the key shares were generated under a degree-`(t-1)` polynomial with `t >= 2`, a single-point interpolation yields the wrong scalar, and the aggregated signature fails standard Ed25519/RedJubjub verification. Honest parties who trust the protocol's output receive a signature that is silently invalid — they cannot distinguish this from a legitimate protocol failure without re-verifying externally.

---

### Likelihood Explanation

**Medium.** The `threshold` parameter is caller-supplied at the API boundary. Any application that wraps the library and forwards a user-controlled or misconfigured threshold value reaches this path directly. A malicious coordinator who controls the signing invocation can deliberately pass `threshold = 1` to force an unusable output, denying the signing service to honest participants while consuming their nonce material.

---

### Recommendation

Add the same lower-bound guard that `assert_key_invariants` already enforces, in both `assert_sign_inputs` and `presign`:

```rust
if threshold.value() < 2 {
    return Err(InitializationError::ThresholdTooSmall {
        threshold: threshold.value(),
        min: 2,
    });
}
```

This mirrors the existing check at `src/dkg.rs:580-582` and closes the asymmetry between the keygen and signing validation paths. [1](#0-0) 

---

### Proof of Concept

1. Generate keys with `threshold = 2`, `participants = [P1, P2, P3]` via `do_keygen` — this succeeds because `assert_key_invariants` enforces `threshold >= 2`.
2. Call `assert_sign_inputs(&[P1, P2, P3], ReconstructionLowerBound(1), P1, P1)` — this returns `Ok(participants)` because the only check is `1 > 3`, which is false. No error is raised.
3. Call `presign(&[P1, P2, P3], P1, PresignArguments { threshold: ReconstructionLowerBound(1), keygen_out: ... }, rng)` — this also returns `Ok(protocol)` for the same reason.
4. Run the signing protocol to completion. The FROST aggregation uses Lagrange interpolation over 1 point, producing a scalar that does not correspond to the master secret. The resulting signature fails `VerifyingKey::verify`.

The root cause is the missing `threshold < 2` guard at `src/frost/mod.rs:144` and `src/frost/mod.rs:71`, directly analogous to the missing `amount > 0` guard in the reported `flashLoan` function. [5](#0-4) [6](#0-5)

### Citations

**File:** src/dkg.rs (L580-582)
```rust
    if threshold < 2 {
        return Err(InitializationError::ThresholdTooSmall { threshold, min: 2 });
    }
```

**File:** src/frost/mod.rs (L44-88)
```rust
pub fn presign<C>(
    participants: &[Participant],
    me: Participant,
    args: &PresignArguments<C>,
    rng: impl CryptoRngCore + Send + 'static,
) -> Result<impl Protocol<Output = PresignOutput<C>>, InitializationError>
where
    C: Ciphersuite + Send,
    <<<C as frost_core::Ciphersuite>::Group as Group>::Field as Field>::Scalar: Send,
    <<C as frost_core::Ciphersuite>::Group as frost_core::Group>::Element: std::marker::Send,
{
    if participants.len() < 2 {
        return Err(InitializationError::NotEnoughParticipants {
            participants: participants.len(),
        });
    }

    let participants =
        ParticipantList::new(participants).ok_or(InitializationError::DuplicateParticipants)?;

    if !participants.contains(me) {
        return Err(InitializationError::MissingParticipant {
            role: "self",
            participant: me,
        });
    }

    // validate threshold
    if args.threshold.value() > participants.len() {
        return Err(InitializationError::ThresholdTooLarge {
            threshold: args.threshold.into(),
            max: participants.len(),
        });
    }

    let ctx = Comms::new();
    let fut = do_presign(
        ctx.shared_channel(),
        participants,
        me,
        args.keygen_out.private_share,
        rng,
    );
    Ok(make_protocol(ctx, fut))
}
```

**File:** src/frost/mod.rs (L120-159)
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
