### Title
Missing Lower-Bound Threshold Validation in FROST Signing Path Allows Threshold=1 (or 0) to Proceed - (File: src/frost/mod.rs)

### Summary
`assert_sign_inputs` and `presign` in `src/frost/mod.rs` omit the `threshold < 2` lower-bound check that is present in `assert_key_invariants` (`src/dkg.rs`). A caller can supply `threshold = 1` (or `0`) to the FROST signing path without receiving an error. Because `ReconstructionLowerBound` is an unconstrained `usize` wrapper, any value is accepted. The signing protocol then runs to completion with a cryptographically invalid threshold, producing an unusable signature and consuming single-use presign nonces.

### Finding Description

`assert_key_invariants` in `src/dkg.rs` enforces a minimum threshold of 2:

```rust
// src/dkg.rs lines 580-582
if threshold < 2 {
    return Err(InitializationError::ThresholdTooSmall { threshold, min: 2 });
}
```

The FROST signing validation function `assert_sign_inputs` in `src/frost/mod.rs` only checks the upper bound:

```rust
// src/frost/mod.rs lines 144-150
if threshold.value() > participants.len() {
    return Err(InitializationError::ThresholdTooLarge {
        threshold: threshold.value(),
        max: participants.len(),
    });
}
```

The lower-bound check (`threshold < 2`) is entirely absent. The same omission exists in `presign` at lines 72–77 of `src/frost/mod.rs`.

`ReconstructionLowerBound` is a plain `usize` newtype with `#[derive(From)]`, so `ReconstructionLowerBound::from(1usize)` and `ReconstructionLowerBound::from(0usize)` are both valid at the type level:

```rust
// src/thresholds.rs lines 9-12
pub struct ReconstructionLowerBound(usize);
```

A caller therefore passes `threshold = 1` to `assert_sign_inputs` or `presign`; both functions return `Ok` and the signing protocol proceeds.

### Impact Explanation

**Impact: High — Corruption of sign outputs so honest parties receive unusable cryptographic outputs.**

In FROST signing with `threshold = 1`:
- Only one participant's partial signature is collected.
- The Lagrange coefficient for a single-point interpolation is 1, so the aggregated scalar is `z = nonce_i + challenge × share_i`.
- Because the key was generated with `threshold ≥ 2` (enforced by `assert_key_invariants`), `share_i ≠ secret`. The resulting `(R, z)` pair does not satisfy the Schnorr verification equation against the public key.
- Honest parties receive a structurally complete but cryptographically invalid signature — an unusable output.
- Additionally, FROST nonces are single-use; the consumed presign material cannot be reused, so the signing slot is permanently wasted.

With `threshold = 0`:
- Lagrange interpolation over zero points is undefined; the aggregation step produces a zero/identity scalar or panics, causing the signing protocol to abort with an unrecoverable error.

### Likelihood Explanation

**Likelihood: 2 out of 10.**

The caller must explicitly construct a `ReconstructionLowerBound` with value 1 or 0 and pass it to the FROST signing entry point. This is an input-validation gap reachable by any library caller (including a malicious coordinator who controls the threshold parameter passed to `assert_sign_inputs`). It does not require key compromise or network access beyond normal protocol participation.

### Recommendation

Add the same lower-bound guard that exists in `assert_key_invariants` to both `assert_sign_inputs` and `presign` in `src/frost/mod.rs`:

```rust
if threshold.value() < 2 {
    return Err(InitializationError::ThresholdTooSmall {
        threshold: threshold.value(),
        min: 2,
    });
}
```

Optionally, enforce the minimum at construction time inside `ReconstructionLowerBound::new` so the invariant is guaranteed at the type level across all call sites.

### Proof of Concept

1. A key is generated with `threshold = 2` via `keygen` (correctly validated by `assert_key_invariants`).
2. A caller invokes `assert_sign_inputs(participants, 1usize, me, coordinator)`.
3. The function reaches line 145 of `src/frost/mod.rs`: `1 > participants.len()` is `false` (e.g., 3 participants), so no error is returned.
4. The signing protocol runs with `threshold = 1`; only one partial signature is aggregated.
5. The resulting signature fails Schnorr verification against the public key, producing an unusable output and consuming the presign nonces irreversibly.

**Root cause lines:** [1](#0-0) [2](#0-1) 

**Correct guard present in DKG path (absent in signing path):** [3](#0-2) 

**Unconstrained threshold type:** [4](#0-3)

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

**File:** src/dkg.rs (L580-582)
```rust
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
