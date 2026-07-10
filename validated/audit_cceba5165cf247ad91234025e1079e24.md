### Title
Missing Lower-Bound Validation on `threshold` in FROST Signing Initialization Allows Denial of Signing - (File: src/frost/mod.rs)

### Summary
The `assert_sign_inputs` function, which gates all FROST EdDSA and RedJubjub signing entry points, validates that `threshold` is not too large but never checks that `threshold >= 2`. A caller passing `threshold = 0` or `threshold = 1` bypasses the guard, enters the signing protocol, and causes it to fail after nonces and presignatures have been consumed — permanently denying use of those presignatures.

### Finding Description
`assert_sign_inputs` in `src/frost/mod.rs` performs the following threshold checks:

```rust
// validate threshold
if threshold.value() > participants.len() {
    return Err(InitializationError::ThresholdTooLarge { ... });
}
``` [1](#0-0) 

There is no corresponding lower-bound check (`threshold < 2`). Compare this to the analogous guard in `assert_key_invariants` (DKG) and `validate_triple_inputs` (triple generation), both of which explicitly reject sub-minimum thresholds:

```rust
if threshold < 2 {
    return Err(InitializationError::ThresholdTooSmall { threshold, min: 2 });
}
``` [2](#0-1) [3](#0-2) 

`assert_sign_inputs` is the sole validation gate for three public signing entry points:

- `frost::eddsa::sign::sign_v1` — line 47
- `frost::eddsa::sign::sign_v2` — line 73
- `frost::redjubjub::sign::sign` — line 50 [4](#0-3) [5](#0-4) 

When `threshold = 1` passes validation, it is forwarded into `construct_key_package`, which creates a `KeyPackage` with `min_signers = 1`:

```rust
Ok(KeyPackage::new(
    identifier,
    signing_share,
    verifying_share,
    *verifying_key,
    u16::try_from(threshold.value())...,
))
``` [6](#0-5) 

With `min_signers = 1`, `round2::sign` accepts a signing package containing only one commitment. The resulting signature share is computed with a Lagrange coefficient of 1 (single-participant interpolation), which is inconsistent with the DKG polynomial degree. The `aggregate` call then fails because the reconstructed value does not match the public key, returning a `ProtocolError`. For `threshold = 0`, `KeyPackage::new` with `min_signers = 0` may panic or error immediately inside the frost library.

### Impact Explanation
**High — Permanent denial of signing for honest parties.**

For presign-based signing (`sign_v2` / `redjubjub::sign`), the presignature nonces are consumed inside `round2::sign` before the failure is detected. The security documentation explicitly states presignatures must never be reused even across failed sessions:

> *"Never reuse a presignature, even across failed, aborted, or partially completed signing sessions."* [7](#0-6) 

A malicious coordinator or participant who repeatedly initiates signing sessions with `threshold = 1` permanently exhausts the pool of valid presignatures, forcing honest parties to regenerate them. Each failed session irreversibly destroys one presignature, making the denial of signing durable and cumulative.

### Likelihood Explanation
The `threshold` parameter is caller-supplied with no type-level enforcement of a minimum value. `ReconstructionLowerBound` is a plain `usize` wrapper with no invariant:

```rust
pub struct ReconstructionLowerBound(usize);
``` [8](#0-7) 

Any unprivileged library caller — including a malicious coordinator or a single compromised participant — can pass `threshold = 1` directly to `sign_v1`, `sign_v2`, or `redjubjub::sign`. No special privilege or key material is required to trigger the failure.

### Recommendation
Add the same lower-bound guard that exists in `assert_key_invariants` and `validate_triple_inputs` to `assert_sign_inputs`:

```rust
if threshold.value() < 2 {
    return Err(InitializationError::ThresholdTooSmall {
        threshold: threshold.value(),
        min: 2,
    });
}
``` [9](#0-8) 

Apply the same fix to the `presign` function in `src/frost/mod.rs`, which also accepts `threshold` without a lower-bound check. [10](#0-9) 

### Proof of Concept

```rust
// Attacker (malicious coordinator) calls sign_v2 with threshold = 1
// even though DKG was performed with threshold = 3.
// assert_sign_inputs passes because 1 <= participants.len() and 1 > 0.
// construct_key_package creates KeyPackage with min_signers = 1.
// round2::sign computes share with Lagrange coefficient = 1 (wrong).
// aggregate fails: reconstructed value ≠ public key.
// The presignature nonces are consumed and cannot be reused.

let result = frost::eddsa::sign::sign_v2(
    &participants,
    1usize,          // threshold = 1, bypasses assert_sign_inputs
    me,
    coordinator,
    keygen_output,   // produced by DKG with threshold = 3
    presignature,    // now permanently consumed
    message,
);
// result is Ok(...) — protocol starts
// protocol terminates with ProtocolError::AssertionFailed from aggregate
// presignature is irrecoverably spent
``` [11](#0-10) [12](#0-11)

### Citations

**File:** src/frost/mod.rs (L71-77)
```rust
    // validate threshold
    if args.threshold.value() > participants.len() {
        return Err(InitializationError::ThresholdTooLarge {
            threshold: args.threshold.into(),
            max: participants.len(),
        });
    }
```

**File:** src/frost/mod.rs (L119-160)
```rust
/// Verifies that the sign inputs are valid
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

**File:** src/dkg.rs (L580-582)
```rust
    if threshold < 2 {
        return Err(InitializationError::ThresholdTooSmall { threshold, min: 2 });
    }
```

**File:** src/ecdsa/ot_based_ecdsa/triples/generation.rs (L699-704)
```rust
    if threshold_value < 2 {
        return Err(InitializationError::ThresholdTooSmall {
            threshold: threshold_value,
            min: 2,
        });
    }
```

**File:** src/frost/eddsa/sign.rs (L46-47)
```rust
    let threshold = threshold.into();
    let participants = assert_sign_inputs(participants, threshold, me, coordinator)?;
```

**File:** src/frost/eddsa/sign.rs (L64-88)
```rust
pub fn sign_v2(
    participants: &[Participant],
    threshold: impl Into<ReconstructionLowerBound> + Copy,
    me: Participant,
    coordinator: Participant,
    keygen_output: KeygenOutput,
    presignature: PresignOutput,
    message: Vec<u8>,
) -> Result<impl Protocol<Output = SignatureOption>, InitializationError> {
    let participants = assert_sign_inputs(participants, threshold, me, coordinator)?;

    let comms = Comms::new();
    let chan = comms.shared_channel();
    let fut = fut_wrapper_v2(
        chan,
        participants,
        threshold.into(),
        me,
        coordinator,
        keygen_output,
        presignature,
        message,
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

**File:** src/frost/redjubjub/sign.rs (L49-50)
```rust
    let threshold = threshold.into();
    let participants = assert_sign_inputs(participants, threshold, me, coordinator)?;
```

**File:** docs/ecdsa/robust_ecdsa/signing.md (L176-178)
```markdown
3. **Never reuse a presignature**, even across failed, aborted, or partially completed
   signing sessions.

```

**File:** src/thresholds.rs (L12-12)
```rust
pub struct ReconstructionLowerBound(usize);
```
