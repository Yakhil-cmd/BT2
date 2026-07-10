### Title
Missing Minimum Threshold Lower-Bound Validation in FROST Signing Allows Corrupted Signing Outputs - (File: src/frost/mod.rs)

### Summary

`assert_sign_inputs` in `src/frost/mod.rs`, which gates all FROST EdDSA and RedJubjub signing calls, validates only the upper bound on `threshold` (must not exceed participant count) but omits the lower-bound check (`threshold >= 2`) that is consistently enforced in every other protocol entry point in the library. A caller supplying `threshold = 1` (or `0`) bypasses this guard, causing the FROST signing protocol to aggregate only a single participant's signature share via a degenerate Lagrange interpolation, producing an invalid/unusable signature that honest participants accept as the protocol output.

### Finding Description

`assert_key_invariants` in `src/dkg.rs` enforces both bounds:

```rust
if threshold > participants.len() {
    return Err(InitializationError::ThresholdTooLarge { ... });
}
if threshold < 2 {
    return Err(InitializationError::ThresholdTooSmall { threshold, min: 2 });
}
``` [1](#0-0) 

`validate_triple_inputs` in the OT-based ECDSA triple generation also enforces both bounds:

```rust
if threshold_value > participants.len() { ... }
if threshold_value < 2 { return Err(ThresholdTooSmall { ... }); }
``` [2](#0-1) 

By contrast, `assert_sign_inputs` in `src/frost/mod.rs` only checks the upper bound:

```rust
// validate threshold
if threshold.value() > participants.len() {
    return Err(InitializationError::ThresholdTooLarge { ... });
}
// ← no lower-bound check; threshold = 1 or 0 passes silently
``` [3](#0-2) 

`assert_sign_inputs` is the sole validation gate called by all three FROST signing entry points:

- `frost::eddsa::sign::sign_v1` and `sign_v2` [4](#0-3) 
- `frost::redjubjub::sign::sign` [5](#0-4) 

The same lower-bound omission exists in the FROST `presign` function:

```rust
if args.threshold.value() > participants.len() {
    return Err(InitializationError::ThresholdTooLarge { ... });
}
// ← no threshold < 2 check
``` [6](#0-5) 

`ReconstructionLowerBound` is a plain `usize` wrapper with no enforced minimum, so `threshold = 1` or `threshold = 0` is a valid value at the type level: [7](#0-6) 

### Impact Explanation

With `threshold = 1`, the FROST signing protocol collects only one participant's nonce commitment and one signature share. The Lagrange coefficient for a single-element set is 1, so the aggregated signature is `z = k_i + x_i * c` — a signature under participant `i`'s individual share `x_i`, not under the group secret key `x`. Since DKG enforces `threshold >= 2`, `x_i != x` in all valid key setups, and the resulting `(R, z)` pair fails verification against the group public key. Honest participants accept this unusable output as the completed signing protocol result, permanently corrupting the signing session.

This maps to: **High — Corruption of sign outputs so honest parties accept unusable cryptographic outputs.**

### Likelihood Explanation

Any unprivileged library caller who invokes `sign_v1`, `sign_v2`, or `redjubjub::sign` controls the `threshold` argument directly. No special privilege, leaked key material, or cryptographic break is required. The missing check is a single missing `if threshold < 2` guard that is present in every analogous function in the same codebase, making accidental or malicious misuse straightforward.

### Recommendation

Add the same lower-bound guard present in `assert_key_invariants` and `validate_triple_inputs` to `assert_sign_inputs` and to the FROST `presign` function:

```rust
if threshold.value() < 2 {
    return Err(InitializationError::ThresholdTooSmall {
        threshold: threshold.value(),
        min: 2,
    });
}
```

This should be inserted immediately after the upper-bound check in both `assert_sign_inputs` (line 150) and `presign` (line 77) in `src/frost/mod.rs`.

### Proof of Concept

1. Run DKG with 3 participants and `threshold = 2` (succeeds, enforced by `assert_key_invariants`).
2. Call `frost::eddsa::sign::sign_v1` with the same 3 participants but `threshold = 1`.
3. `assert_sign_inputs` passes: `1 <= 3` satisfies the only check.
4. The protocol collects 1 nonce commitment and 1 signature share.
5. FROST aggregation produces `(R, z)` where `z = k_i + x_i * c`.
6. Verification against the group public key `Y` fails: `z * G = R_i + Y_i * c ≠ R + Y * c`.
7. All honest participants receive and accept this invalid signature as the protocol output.

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

**File:** src/ecdsa/ot_based_ecdsa/triples/generation.rs (L692-704)
```rust
    // Spec 1.1
    if threshold_value > participants.len() {
        return Err(InitializationError::ThresholdTooLarge {
            threshold: threshold_value,
            max: participants.len(),
        });
    }
    if threshold_value < 2 {
        return Err(InitializationError::ThresholdTooSmall {
            threshold: threshold_value,
            min: 2,
        });
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

**File:** src/frost/mod.rs (L144-150)
```rust
    // validate threshold
    if threshold.value() > participants.len() {
        return Err(InitializationError::ThresholdTooLarge {
            threshold: threshold.value(),
            max: participants.len(),
        });
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
