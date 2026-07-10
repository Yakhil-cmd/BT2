### Title
Missing Lower-Bound Validation on `threshold` in FROST Signing Allows Degenerate-Threshold Signing Sessions — (File: `src/frost/mod.rs`)

---

### Summary

`assert_sign_inputs` validates the `threshold` parameter only with an upper-bound check (`threshold > participants.len()`), but never enforces a lower bound (`threshold >= 2`). A malicious coordinator or library caller can pass `threshold = 0` (or `threshold = 1`), which silently passes all guards and causes the FROST signing protocol to proceed with a `KeyPackage` whose `min_signers = 0`. This allows honest participants to accept and sign a `SigningPackage` that contains fewer commitments than the actual DKG security threshold, producing an unusable aggregate signature and corrupting the sign output.

---

### Finding Description

**Analog to the external report:** In the Solidity bug, `fillAmount == 0` passes the guard `if (fillAmount > orderHashToRemainingQuantity[orderHash]) revert` because zero is never greater than anything, and execution continues with default/uninitialized market state. The exact same structural flaw exists here: `threshold == 0` passes the guard `if threshold.value() > participants.len()` because zero is never greater than `participants.len()` (which is at least 2), and signing proceeds with a degenerate threshold of zero.

**Root cause — `assert_sign_inputs` in `src/frost/mod.rs`:**

```rust
// validate threshold
if threshold.value() > participants.len() {
    return Err(InitializationError::ThresholdTooLarge { ... });
}
``` [1](#0-0) 

There is no corresponding lower-bound check. Compare this to `assert_key_invariants` in `src/dkg.rs`, which correctly enforces both bounds:

```rust
if threshold > participants.len() { ... }
// Step 1.1
if threshold < 2 {
    return Err(InitializationError::ThresholdTooSmall { threshold, min: 2 });
}
``` [2](#0-1) 

The lower-bound check exists for DKG but is entirely absent from the signing validation path.

**Propagation — `construct_key_package` in `src/frost/eddsa/sign.rs`:**

The unchecked `threshold` is passed directly into `KeyPackage::new` as `min_signers`:

```rust
Ok(KeyPackage::new(
    identifier,
    signing_share,
    verifying_share,
    *verifying_key,
    u16::try_from(threshold.value()).map_err(|_| { ... })?,
))
``` [3](#0-2) 

With `threshold = 0`, `min_signers = 0u16` is passed to the FROST library. The FROST library's `round2::sign` checks that the `SigningPackage` has at least `min_signers` commitments. With `min_signers = 0`, this check always passes unconditionally.

**Entry points — `sign_v1` and `sign_v2` in `src/frost/eddsa/sign.rs`:**

Both public signing functions delegate directly to `assert_sign_inputs` without any additional threshold validation:

```rust
pub fn sign_v1(..., threshold: impl Into<ReconstructionLowerBound>, ...) -> ... {
    let threshold = threshold.into();
    let participants = assert_sign_inputs(participants, threshold, me, coordinator)?;
    ...
}
``` [4](#0-3) 

The same flaw is present in `presign` in `src/frost/mod.rs`:

```rust
if args.threshold.value() > participants.len() {
    return Err(InitializationError::ThresholdTooLarge { ... });
}
``` [5](#0-4) 

No lower-bound check exists here either.

**`ReconstructionLowerBound` has no minimum enforcement:**

The type itself is a plain `usize` wrapper with no invariant:

```rust
pub struct ReconstructionLowerBound(usize);
impl ReconstructionLowerBound {
    pub fn value(self) -> usize { self.0 }
}
``` [6](#0-5) 

Any `usize` value, including 0, is accepted.

---

### Impact Explanation

A malicious coordinator calls `sign_v1` (or `sign_v2`) with `threshold = 0`. `assert_sign_inputs` passes all checks. `construct_key_package` creates a `KeyPackage` with `min_signers = 0`. The FROST library's `round2::sign` then accepts any `SigningPackage` regardless of how many commitments it contains. The coordinator can send a `SigningPackage` containing only their own commitment; honest participants call `round2::sign` with `min_signers = 0`, which passes, and they produce and send signature shares. The coordinator aggregates using only their own share. The resulting aggregate signature is computed over a participant set inconsistent with the DKG threshold, producing a cryptographic output that fails verification against the group public key — an unusable, corrupted sign output.

This maps to: **High — Corruption of sign outputs so honest parties accept inconsistent participant sets and produce unusable cryptographic outputs.**

---

### Likelihood Explanation

The `threshold` parameter is caller-supplied with no type-level enforcement of a minimum value. Any library caller acting as coordinator can trivially pass `0` or `1`. The flaw requires no special cryptographic capability — only the ability to call the public API with an out-of-range parameter. The inconsistency between `assert_key_invariants` (which enforces `threshold >= 2`) and `assert_sign_inputs` (which does not) makes this easy to trigger accidentally or maliciously.

---

### Recommendation

Add the same lower-bound check to `assert_sign_inputs` (and to `presign`) that already exists in `assert_key_invariants`:

```rust
// In assert_sign_inputs (src/frost/mod.rs)
if threshold.value() < 2 {
    return Err(InitializationError::ThresholdTooSmall {
        threshold: threshold.value(),
        min: 2,
    });
}
```

Apply the same guard to the `presign` function's threshold validation. Alternatively, enforce the invariant at the type level by making `ReconstructionLowerBound::new` a checked constructor that rejects values below 2.

---

### Proof of Concept

1. Run DKG with 3 participants and `threshold = 2` (passes `assert_key_invariants`).
2. Call `sign_v1` with the same 3 participants but `threshold = 0`:
   - `assert_sign_inputs` checks `0 > 3` → false → no error returned.
   - `construct_key_package` is called with `threshold.value() = 0` → `KeyPackage::new(..., 0u16)`.
3. The coordinator constructs a `SigningPackage` containing only their own commitment (1 entry).
4. Each participant calls `round2::sign` with `min_signers = 0` → the check `commitments.len() >= min_signers` evaluates to `1 >= 0` → passes.
5. Participants send signature shares to the coordinator.
6. The coordinator calls `aggregate` with only their own share (matching the 1 commitment in the `SigningPackage`).
7. The resulting aggregate signature is based on a single participant's share and fails verification against the group public key established during DKG — a corrupted, unusable sign output accepted by all honest participants.

### Citations

**File:** src/frost/mod.rs (L72-77)
```rust
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

**File:** src/dkg.rs (L573-582)
```rust
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
