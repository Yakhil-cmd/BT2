### Title
Missing Lower Bound Validation on `threshold` in `assert_sign_inputs` Allows Malicious Coordinator to Corrupt or Deny FROST Signing - (File: src/frost/mod.rs)

### Summary
The `assert_sign_inputs` function used by all FROST EdDSA and RedJubjub signing entry points validates that `threshold <= participants.len()` (upper bound) but omits the lower bound check `threshold >= 2` that is present in the DKG validation function `assert_key_invariants`. A malicious coordinator or library caller can pass `threshold = 0` or `threshold = 1` to any FROST signing function without triggering an error, causing the coordinator to attempt signature aggregation with fewer shares than the cryptographic security of the key requires.

### Finding Description
`assert_key_invariants` in `src/dkg.rs` enforces both bounds on the threshold parameter:

```rust
if threshold > participants.len() { /* ThresholdTooLarge */ }
if threshold < 2 { /* ThresholdTooSmall */ }
``` [1](#0-0) 

`assert_sign_inputs` in `src/frost/mod.rs`, which gates all FROST signing calls, only enforces the upper bound:

```rust
if threshold.value() > participants.len() { /* ThresholdTooLarge */ }
// ← no lower-bound check
``` [2](#0-1) 

The `ReconstructionLowerBound` type itself performs no validation on construction — it is a plain `usize` newtype derived via `From`: [3](#0-2) 

`assert_sign_inputs` is the sole validation gate for three public signing entry points:

- `sign_v1` / `sign_v2` in `src/frost/eddsa/sign.rs`
- `sign` in `src/frost/redjubjub/sign.rs` [4](#0-3) [5](#0-4) 

### Impact Explanation
When a coordinator passes `threshold = 1` to `sign_v1` or `sign_v2`, the coordinator's signing loop collects only one signature share before calling FROST's `aggregate`. The `SigningPackage` built by the coordinator includes commitments from all participants, but only one `SignatureShare` is provided to `aggregate`. FROST's `aggregate` will either:

1. **Fail outright** because the number of shares does not match the threshold embedded in the `KeyPackage` (set at keygen time to ≥ 2), permanently denying the signing round for all honest participants who have already committed their nonces and are waiting for the result.
2. **Produce a cryptographically invalid signature** if the library does not re-check the `KeyPackage` threshold against the number of provided shares, corrupting the sign output accepted by the coordinator.

With `threshold = 0`, the coordinator attempts aggregation with zero shares, which is guaranteed to produce a corrupt or panicking output.

Both outcomes match the High impact category: honest parties who have completed their presign/commit phase cannot obtain a valid signature, and the coordinator can trigger this condition unilaterally on any signing session.

### Likelihood Explanation
The coordinator role is explicitly untrusted in the documented threat model (the library warns about split-view attacks from a malicious coordinator). Any party acting as coordinator for a FROST EdDSA or RedJubjub signing session can supply an arbitrary `threshold` value. No out-of-band enforcement prevents passing `threshold = 1`. Likelihood is **Medium**: the coordinator must be actively malicious, but the attack requires no cryptographic capability and is trivially reproducible.

### Recommendation
Add the same lower-bound guard that exists in `assert_key_invariants` to `assert_sign_inputs`:

```rust
if threshold.value() < 2 {
    return Err(InitializationError::ThresholdTooSmall {
        threshold: threshold.value(),
        min: 2,
    });
}
```

This should be inserted in `src/frost/mod.rs` immediately after the upper-bound check at line 145, mirroring the pattern at `src/dkg.rs` lines 580–582. [6](#0-5) 

### Proof of Concept
```rust
// Keygen with threshold = 2, participants = [P1, P2, P3]
let keygen_outputs = run_keygen(&participants, threshold_2, &mut rng);

// Malicious coordinator passes threshold = 1 to signing
let result = sign_v1(
    &participants,
    ReconstructionLowerBound::from(1usize), // ← passes assert_sign_inputs unchecked
    me,
    coordinator,
    keygen_outputs[coordinator_idx].clone(),
    message,
    rng,
);
// assert_sign_inputs returns Ok(participants) — no error
// Coordinator collects only 1 share, calls FROST aggregate with 1 share
// Signing fails or produces invalid output; honest participants' nonces are consumed
```

The call to `assert_sign_inputs` with `threshold = 1` and `participants.len() = 3` passes both existing checks (`1 <= 3`, `3 >= 2`) and returns `Ok`, allowing the malformed signing session to proceed. [7](#0-6) [8](#0-7)

### Citations

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

**File:** src/thresholds.rs (L9-12)
```rust
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, From, Into,
)]
pub struct ReconstructionLowerBound(usize);
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

**File:** src/frost/redjubjub/sign.rs (L39-66)
```rust
pub fn sign(
    participants: &[Participant],
    threshold: impl Into<ReconstructionLowerBound>,
    me: Participant,
    coordinator: Participant,
    keygen_output: KeygenOutput,
    presignature: PresignOutput,
    message: Vec<u8>,
    randomizer: Option<Randomizer>,
) -> Result<impl Protocol<Output = SignatureOption>, InitializationError> {
    let threshold = threshold.into();
    let participants = assert_sign_inputs(participants, threshold, me, coordinator)?;

    let comms = Comms::new();
    let chan = comms.shared_channel();
    let fut = fut_wrapper(
        chan,
        participants,
        threshold,
        me,
        coordinator,
        keygen_output,
        presignature,
        message,
        randomizer,
    );
    Ok(make_protocol(comms, fut))
}
```
