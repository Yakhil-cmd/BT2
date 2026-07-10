### Title
Missing Minimum Threshold Validation in FROST Signing Corrupts Signature Output — (File: `src/frost/mod.rs`)

---

### Summary

The `assert_sign_inputs` and `presign` functions in `src/frost/mod.rs` validate that the threshold does not exceed the participant count, but they omit the lower-bound check (`threshold >= 2`) that is explicitly enforced in `assert_key_invariants` (`src/dkg.rs`). A caller can supply `threshold = 1` (or `0`) to the FROST signing path. Because the key shares were generated under a polynomial of degree `threshold − 1 ≥ 1`, using a mismatched threshold of 1 during signing causes every participant to compute Lagrange coefficients for a 1-of-n scheme instead of the correct t-of-n scheme, producing an aggregated signature that is cryptographically invalid and cannot be verified against the public key.

---

### Finding Description

**Root cause — `src/frost/mod.rs`, `assert_sign_inputs` (lines 120–160):**

```rust
pub fn assert_sign_inputs(
    participants: &[Participant],
    threshold: impl Into<ReconstructionLowerBound>,
    me: Participant,
    coordinator: Participant,
) -> Result<ParticipantList, InitializationError> {
    let threshold = threshold.into();
    if participants.len() < 2 {
        return Err(InitializationError::NotEnoughParticipants { ... });
    }
    // ...
    // validate threshold
    if threshold.value() > participants.len() {   // ← only upper-bound check
        return Err(InitializationError::ThresholdTooLarge { ... });
    }
    // ← NO check: threshold.value() < 2
    Ok(participants)
}
``` [1](#0-0) 

**Root cause — `src/frost/mod.rs`, `presign` (lines 44–88):**

```rust
// validate threshold
if args.threshold.value() > participants.len() {   // ← only upper-bound check
    return Err(InitializationError::ThresholdTooLarge { ... });
}
// ← NO check: args.threshold.value() < 2
``` [2](#0-1) 

**Contrast with the DKG path — `src/dkg.rs`, `assert_key_invariants` (lines 558–596):**

```rust
if threshold > participants.len() {
    return Err(InitializationError::ThresholdTooLarge { ... });
}
// Step 1.1
if threshold < 2 {
    return Err(InitializationError::ThresholdTooSmall { threshold, min: 2 });
}
``` [3](#0-2) 

The `ReconstructionLowerBound` type is a plain `usize` wrapper with no invariant enforced at construction time, so any value including `0` and `1` is accepted. [4](#0-3) 

---

### Impact Explanation

**High — Corruption of signing outputs so honest parties accept unusable cryptographic outputs.**

During DKG, `assert_key_invariants` guarantees the polynomial degree is at least 1 (threshold ≥ 2). Each participant's signing share is an evaluation of that polynomial. During FROST signing, each participant computes a Lagrange coefficient relative to the *signing* threshold. If the signing threshold is set to 1, the Lagrange coefficient for any single participant evaluates to 1 (trivially), while the correct coefficient for the actual t-of-n scheme is a non-trivial field element. The aggregated signature shares therefore sum to the wrong value and the resulting signature fails verification against the public key. Honest parties complete the protocol and receive an unusable, invalid signature with no indication that the threshold parameter was wrong.

With `threshold = 0`, the Lagrange interpolation in `participants.lagrange::<C>(me)` operates over an empty identifier set, which can produce a zero coefficient or a division-by-zero panic, further corrupting or aborting the signing session. [5](#0-4) 

---

### Likelihood Explanation

**Medium.** The threshold value is a caller-supplied parameter with no type-level enforcement of a minimum. Any participant acting as a coordinator, or any library integrator who misconfigures the threshold (e.g., passes `1` intending "one-of-n"), triggers this path. No cryptographic capability or key material is required — only the ability to call the public `presign` or `assert_sign_inputs` entry points with an out-of-range threshold.

---

### Recommendation

Add the same lower-bound guard that `assert_key_invariants` already enforces to both `assert_sign_inputs` and `presign` in `src/frost/mod.rs`:

```rust
if threshold.value() < 2 {
    return Err(InitializationError::ThresholdTooSmall {
        threshold: threshold.value(),
        min: 2,
    });
}
```

This should be placed immediately after the upper-bound check in both functions, mirroring the pattern in `src/dkg.rs` lines 580–582. [6](#0-5) 

---

### Proof of Concept

1. Run DKG with `n = 3` participants and `threshold = 2` via `keygen` / `assert_key_invariants`. This succeeds and produces valid key shares.
2. Call `presign` (or `assert_sign_inputs`) with the same participants but `threshold = 1`. Both functions accept this value because only the upper-bound check (`threshold > participants.len()`) is present.
3. Proceed to the FROST signing round. Each participant computes `participants.lagrange::<C>(me)` using the signing-threshold participant set of size 1, yielding coefficient `1` instead of the correct t-of-n Lagrange value.
4. The coordinator aggregates the shares. The resulting `Signature` does not verify against the public key produced in step 1.
5. Honest parties have completed the protocol and accepted an unusable output, with no error returned by the library. [7](#0-6) [8](#0-7)

### Citations

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

**File:** src/dkg.rs (L572-582)
```rust
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

**File:** src/participants.rs (L151-158)
```rust
    pub fn lagrange<C: Ciphersuite>(&self, p: Participant) -> Result<Scalar<C>, ProtocolError> {
        let p = p.scalar::<C>();
        let identifiers: Vec<Scalar<C>> = self
            .participants()
            .iter()
            .map(Participant::scalar::<C>)
            .collect();
        Ok(compute_lagrange_coefficient::<C>(&identifiers, &p, None)?.0)
```
