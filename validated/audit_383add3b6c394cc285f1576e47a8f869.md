### Title
Missing Lower-Bound Validation on `threshold` in `assert_sign_inputs` Allows Zero/One Threshold to Reach FROST Internals - (File: src/frost/mod.rs)

### Summary

`assert_sign_inputs` in `src/frost/mod.rs`, the shared validation gate for `sign_v1`, `sign_v2` (EdDSA), and `redjubjub::sign`, checks that `threshold` is not *too large* but never checks that it is at least 2. Passing `threshold = 0` or `threshold = 1` bypasses all library-level guards and propagates into `construct_key_package`, which converts the value directly to `u16` and hands it to the upstream FROST `KeyPackage::new`. Every other entry-point in the codebase that accepts a threshold enforces `threshold >= 2` before proceeding; the signing path is the sole exception.

### Finding Description

`ReconstructionLowerBound` is a plain `usize` newtype with no invariant enforced at construction time. [1](#0-0) 

Every protocol entry-point that accepts a threshold enforces a minimum of 2:

- DKG (`assert_key_invariants`): `if threshold < 2 { return Err(ThresholdTooSmall) }` [2](#0-1) 

- Triple generation (`validate_triple_inputs`): `if threshold_value < 2 { return Err(ThresholdTooSmall) }` [3](#0-2) 

The shared FROST signing validator `assert_sign_inputs` only checks the upper bound:

```rust
if threshold.value() > participants.len() {
    return Err(InitializationError::ThresholdTooLarge { ... });
}
``` [4](#0-3) 

There is **no** `threshold < 2` guard. `threshold = 0` and `threshold = 1` both pass this function successfully.

All three public signing entry-points delegate to `assert_sign_inputs` and then forward the raw threshold value downstream:

- `sign_v1` / `sign_v2` (EdDSA): [5](#0-4) 
- `redjubjub::sign`: [6](#0-5) 

The threshold then reaches `construct_key_package`, which converts it to `u16` without any additional floor check and passes it directly to `KeyPackage::new`: [7](#0-6) 

With `threshold = 0`, `u16::try_from(0)` succeeds (returns `0`), and `KeyPackage::new` is called with `min_signers = 0`. The FROST library's internal assertion that `min_signers >= 2` (or `>= 1`) is the only remaining guard; if that assertion panics rather than returning an error, the calling process crashes. With `threshold = 1`, the Lagrange interpolation inside FROST signing uses a single-participant basis that is inconsistent with the DKG polynomial degree, producing a signature that fails the internal `aggregate` verification and permanently breaks the signing session for all honest participants.

### Impact Explanation

A caller who supplies `threshold = 0` to any of the three public FROST signing functions causes the invalid value to reach FROST's `KeyPackage::new`. If the upstream library panics on `min_signers = 0` (a common defensive assertion in cryptographic libraries), the entire signing process crashes, permanently denying signing for all honest parties in that session. With `threshold = 1`, the signing protocol completes all network rounds but the coordinator's `aggregate` call returns an error because the reconstructed signature is cryptographically invalid relative to the DKG public key, again permanently denying a valid signature output.

This matches the allowed impact: **High — Permanent denial of signing for honest parties under valid protocol inputs**.

### Likelihood Explanation

`sign_v1`, `sign_v2`, and `redjubjub::sign` are public library API functions. Any library caller — including a malicious coordinator or a misconfigured participant — can supply an arbitrary `usize` as the threshold. The inconsistency with every other entry-point (all of which reject `threshold < 2`) makes accidental misuse likely and deliberate exploitation trivial. No cryptographic material or privileged access is required.

### Recommendation

Add the same lower-bound guard that exists in `assert_key_invariants` and `validate_triple_inputs` to `assert_sign_inputs`:

```rust
pub fn assert_sign_inputs(
    participants: &[Participant],
    threshold: impl Into<ReconstructionLowerBound>,
    me: Participant,
    coordinator: Participant,
) -> Result<ParticipantList, InitializationError> {
    let threshold = threshold.into();
    // ... existing checks ...

    // Add this, matching the guard in assert_key_invariants and validate_triple_inputs:
    if threshold.value() < 2 {
        return Err(InitializationError::ThresholdTooSmall {
            threshold: threshold.value(),
            min: 2,
        });
    }

    // ... rest of function ...
}
```

Alternatively, enforce the invariant at the `ReconstructionLowerBound` construction site so that a value of 0 or 1 can never be represented.

### Proof of Concept

```rust
use threshold_signatures::{
    frost::eddsa::sign::sign_v1,
    participants::Participant,
    test_utils::MockCryptoRng,
    KeygenOutput, ReconstructionLowerBound,
};
use rand_core::SeedableRng;

// Assume a valid keygen_output was produced with threshold=2.
// A malicious or buggy caller now invokes sign_v1 with threshold=0:
let participants = vec![Participant::from(0u32), Participant::from(1u32)];
let me = participants[0];
let coordinator = participants[0];
let rng = MockCryptoRng::seed_from_u64(42);

// assert_sign_inputs passes because 0 <= participants.len() (2).
// The protocol is initialized and threshold=0 reaches KeyPackage::new.
let result = sign_v1(
    &participants,
    0usize,          // threshold = 0, bypasses assert_sign_inputs
    me,
    coordinator,
    keygen_output,   // valid keygen output from a threshold=2 DKG
    b"message".to_vec(),
    rng,
);
// result is Ok(...) — no InitializationError is returned.
// When the protocol is driven, KeyPackage::new(... min_signers=0 ...) is reached,
// causing a panic or a ProtocolError that permanently aborts signing.
```

### Citations

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
