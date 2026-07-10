### Title
Missing Lower-Bound Threshold Validation in `assert_sign_inputs` Allows FROST Signing to Proceed with Threshold=1 — (File: src/frost/mod.rs)

---

### Summary

`assert_sign_inputs` in `src/frost/mod.rs` validates that the threshold does not exceed the participant count but omits the lower-bound check (`threshold >= 2`) that is explicitly enforced in `assert_key_invariants` in `src/dkg.rs`. A caller can pass `threshold = 1` to the FROST signing entry point; the guard passes without error, the protocol executes with a single-participant Lagrange basis, and the resulting signature is cryptographically invalid against the public key that was generated under `threshold >= 2`.

---

### Finding Description

`assert_key_invariants` in `src/dkg.rs` enforces both bounds on the threshold:

```rust
// upper bound
if threshold > participants.len() {
    return Err(InitializationError::ThresholdTooLarge { … });
}
// lower bound  ← present here
if threshold < 2 {
    return Err(InitializationError::ThresholdTooSmall { threshold, min: 2 });
}
``` [1](#0-0) 

`assert_sign_inputs` in `src/frost/mod.rs` only enforces the upper bound and silently omits the lower bound:

```rust
// validate threshold
if threshold.value() > participants.len() {
    return Err(InitializationError::ThresholdTooLarge { … });
}
// ← no threshold < 2 check
``` [2](#0-1) 

`ReconstructionLowerBound` is a plain newtype wrapper with no constructor-level validation, so any `usize` value — including `1` or `0` — is accepted without error: [3](#0-2) 

The `presign` function in `src/frost/mod.rs` has the same gap — it checks the upper bound but not the lower bound: [4](#0-3) 

When `threshold = 1` reaches the FROST signing layer, the Lagrange coefficient for the single contributing participant evaluates to `1` (trivially, since it is the only point). The signature share is therefore computed directly from that participant's secret share rather than from the reconstructed aggregate secret. The resulting `(R, s)` pair fails verification against the public key, which was derived from the full `t`-of-`n` secret.

---

### Impact Explanation

**High — Corruption of sign outputs so honest parties receive unusable cryptographic outputs.**

Any library caller (including a malicious coordinator) who supplies `threshold = 1` to the FROST signing API causes the protocol to complete without an `InitializationError`, yet produces a signature that is cryptographically invalid. Honest participants who rely on the output cannot produce a usable signature for the session. Because the key was generated under `threshold >= 2` (enforced by `assert_key_invariants`), no re-attempt with the same session parameters can recover a valid signature; the session must be aborted and restarted.

---

### Likelihood Explanation

**Medium.** The entry point is a public library API. Any caller — including an integrator, a malicious coordinator, or a test harness — can supply an arbitrary `ReconstructionLowerBound` value. No privileged key material or out-of-band compromise is required. The inconsistency between `assert_key_invariants` and `assert_sign_inputs` means the gap is not obvious from reading either function in isolation.

---

### Recommendation

Add the same lower-bound guard to `assert_sign_inputs` (and to the inline check in `presign`) that already exists in `assert_key_invariants`:

```rust
if threshold.value() < 2 {
    return Err(InitializationError::ThresholdTooSmall {
        threshold: threshold.value(),
        min: 2,
    });
}
```

Place this check immediately after the upper-bound check in both `assert_sign_inputs` (line 150) and `presign` (line 77) in `src/frost/mod.rs`. [5](#0-4) 

---

### Proof of Concept

1. Run DKG with 3 participants and `threshold = 2` via `assert_key_invariants` — succeeds normally.
2. Call `assert_sign_inputs` with the same 3 participants but `threshold = 1`.
3. Observe: no `InitializationError` is returned; the function returns `Ok(participants)`.
4. The FROST signing protocol executes; the single contributing participant's Lagrange coefficient is `1`, so its raw share is used as the signing scalar.
5. The produced signature `(R, s)` fails `verify` against the public key, yielding an unusable output.

The root cause is the missing `threshold < 2` guard at `src/frost/mod.rs` lines 144–150, in contrast to the complete guard at `src/dkg.rs` lines 573–582. [6](#0-5) [7](#0-6)

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
