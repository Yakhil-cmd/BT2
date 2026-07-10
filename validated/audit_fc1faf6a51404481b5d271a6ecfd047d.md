### Title
Missing Minimum Threshold Validation in FROST Signing Allows Sub-Security Threshold Invocation - (`File: src/frost/mod.rs`)

### Summary

`assert_sign_inputs` in `src/frost/mod.rs` validates that `threshold <= participants.len()` but omits the lower-bound check `threshold >= 2` that is explicitly enforced in `assert_key_invariants` (`src/dkg.rs`). A library caller can therefore invoke FROST signing (`sign_v1`, `sign_v2`, `redjubjub::sign`) with `threshold = 1` (or `0`), bypassing the minimum security requirement that was enforced at key-generation time.

### Finding Description

`assert_key_invariants` in `src/dkg.rs` enforces a hard lower bound:

```rust
if threshold < 2 {
    return Err(InitializationError::ThresholdTooSmall { threshold, min: 2 });
}
``` [1](#0-0) 

`assert_sign_inputs` in `src/frost/mod.rs`, which gates every FROST signing entry-point, performs only an upper-bound check and never a lower-bound check:

```rust
// validate threshold
if threshold.value() > participants.len() {
    return Err(InitializationError::ThresholdTooLarge { ... });
}
// ← no check: threshold.value() < 2
``` [2](#0-1) 

`ReconstructionLowerBound` is a plain `usize` newtype with no enforced minimum: [3](#0-2) 

Both `frost::eddsa::sign_v2` and `frost::redjubjub::sign` delegate directly to `assert_sign_inputs` without any additional threshold floor check: [4](#0-3) [5](#0-4) 

The same gap exists in `frost::presign`, which also validates only the upper bound: [6](#0-5) 

### Impact Explanation

FROST secret-sharing is defined over polynomials of degree `threshold − 1`. With `threshold = 1` the polynomial is degree 0 (a constant), meaning a single participant's share alone reconstructs the secret. Invoking signing with `threshold = 1` while the key was generated at `threshold ≥ 2` causes Lagrange interpolation to be performed with the wrong degree, producing either:

1. **Cryptographically invalid / unusable signatures** — honest parties complete the protocol and accept an output that fails external verification (corruption of signing output).
2. **Signing failure** — the FROST library's internal `KeyPackage` threshold check detects the mismatch and aborts, permanently denying signing for that invocation.

Both outcomes map to the allowed High impact: *Corruption of sign outputs so honest parties accept unusable cryptographic outputs* or *Permanent denial of signing for honest parties under valid protocol inputs*.

### Likelihood Explanation

`ReconstructionLowerBound` is constructed directly from a `usize` with no enforced minimum. Any library caller — including an application developer who misreads the API, or a malicious coordinator who supplies parameters to participants — can pass `threshold = 1`. The DKG path correctly rejects this value, creating a false sense of security: developers who test key generation see the guard, but the signing path silently accepts the same invalid value.

### Recommendation

Add the same lower-bound guard to `assert_sign_inputs` that already exists in `assert_key_invariants`:

```rust
if threshold.value() < 2 {
    return Err(InitializationError::ThresholdTooSmall {
        threshold: threshold.value(),
        min: 2,
    });
}
```

Apply the same fix to the `presign` validation in `src/frost/mod.rs`. Consider also enforcing the minimum inside `ReconstructionLowerBound::from` / a dedicated constructor so the invariant is impossible to violate at the type level.

### Proof of Concept

```rust
use threshold_signatures::{
    frost::eddsa::sign_v1,
    participants::Participant,
    ReconstructionLowerBound,
};

let participants = vec![Participant::from(0u32), Participant::from(1u32)];
let me = participants[0];
let coordinator = participants[0];

// threshold = 1 passes assert_sign_inputs (1 <= 2) but violates the
// security minimum enforced during DKG (threshold >= 2).
let result = sign_v1(
    &participants,
    ReconstructionLowerBound::from(1usize), // ← should be rejected
    me,
    coordinator,
    keygen_output,   // generated with threshold = 2
    presign_output,
    message,
);
// Returns Ok(...) instead of Err(ThresholdTooSmall { threshold: 1, min: 2 })
```

The call succeeds past `assert_sign_inputs` because the only threshold check performed is `1 > 2` (false). The signing protocol then proceeds with a threshold inconsistent with the key material, producing an unusable or invalid signature. [7](#0-6) [8](#0-7)

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

**File:** src/frost/redjubjub/sign.rs (L39-65)
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
```
