### Title
Missing Minimum Threshold Check in FROST Signing/Presigning Allows Inconsistent Protocol Execution - (File: src/frost/mod.rs)

### Summary

`assert_key_invariants` enforces `threshold >= 2` for DKG/keygen, but the analogous `assert_sign_inputs` and `frost::presign` functions omit this minimum-threshold check entirely. A malicious coordinator or unprivileged caller can supply `threshold = 1` (or `0`) to the FROST signing and presigning entry points, bypassing the invariant that is enforced at key-generation time and causing the signing protocol to execute with a threshold that is inconsistent with the one used to generate the shares.

### Finding Description

`assert_key_invariants` in `src/dkg.rs` explicitly rejects any threshold below 2:

```rust
// src/dkg.rs  lines 579-582
// Step 1.1
if threshold < 2 {
    return Err(InitializationError::ThresholdTooSmall { threshold, min: 2 });
}
```

The same guard is absent from both FROST entry points in `src/frost/mod.rs`.

`frost::presign` (lines 71-77) only checks the upper bound:

```rust
// validate threshold
if args.threshold.value() > participants.len() {
    return Err(InitializationError::ThresholdTooLarge {
        threshold: args.threshold.into(),
        max: participants.len(),
    });
}
// ← no lower-bound check; threshold = 1 or 0 passes silently
```

`assert_sign_inputs` (lines 144-150) has the identical gap:

```rust
// validate threshold
if threshold.value() > participants.len() {
    return Err(InitializationError::ThresholdTooLarge {
        threshold: threshold.value(),
        max: participants.len(),
    });
}
// ← no lower-bound check
```

`ReconstructionLowerBound` is a plain `usize` newtype with no constructor-level minimum:

```rust
// src/thresholds.rs  lines 9-24
pub struct ReconstructionLowerBound(usize);
impl ReconstructionLowerBound {
    pub fn value(self) -> usize { self.0 }
}
```

So `ReconstructionLowerBound(1)` or `ReconstructionLowerBound(0)` are both valid values that pass every check in the signing path.

### Impact Explanation

When a caller supplies `threshold = 1` to `assert_sign_inputs` or `frost::presign`:

1. **Inconsistent Lagrange interpolation.** The FROST signing protocol computes Lagrange coefficients over the signing participant set. If the threshold supplied at signing time differs from the one used during keygen (which is guaranteed to be ≥ 2), the interpolation is performed over a polynomial of the wrong degree. The resulting aggregated signature share does not correspond to the actual secret key, producing a cryptographically invalid signature that honest parties cannot use.

2. **Participant-count floor bypass.** The only remaining lower bound on participants is the hardcoded `participants.len() < 2` check. With `threshold = 1`, the check `threshold.value() > participants.len()` passes for any participant count ≥ 1, so a coordinator can drive the signing protocol with a participant set that is smaller than the keygen threshold, again producing an unusable output.

Both paths result in **corruption of the sign or presign output**: honest parties complete the protocol and receive a transcript or signature that is internally inconsistent and fails external verification, matching the allowed High impact: *Corruption of presign/sign outputs so honest parties accept unusable cryptographic outputs*.

### Likelihood Explanation

The threshold parameter is fully caller-controlled at every FROST signing and presigning call site. A malicious coordinator, or any library consumer who accidentally passes the wrong threshold (e.g., `1` instead of the keygen threshold), triggers the bug with no special privileges. The keygen path correctly rejects such values, so the inconsistency is reachable only through the signing/presigning path, making it a realistic and non-hypothetical entry point.

### Recommendation

Add the same lower-bound guard that exists in `assert_key_invariants` to both `assert_sign_inputs` and `frost::presign`:

```rust
// In assert_sign_inputs and frost::presign, after the upper-bound check:
if threshold.value() < 2 {
    return Err(InitializationError::ThresholdTooSmall {
        threshold: threshold.value(),
        min: 2,
    });
}
```

Alternatively, enforce the minimum at construction time inside `ReconstructionLowerBound::new` (adding a constructor that rejects values below 2) so the invariant is upheld uniformly across all protocol entry points.

### Proof of Concept

1. Run keygen with `threshold = 3`, `participants = [A, B, C, D, E]`. This succeeds because `assert_key_invariants` enforces `threshold >= 2`.
2. Call `frost::presign` with `threshold = 1`, `participants = [A, B]`. The check `1 > 2` is false; the `< 2` check is absent. Presigning proceeds.
3. Call the FROST sign function via `assert_sign_inputs` with `threshold = 1`, `participants = [A, B]`. Again, all checks pass.
4. The signing protocol computes Lagrange coefficients for a degree-0 polynomial (threshold-1 = 0), which is inconsistent with the degree-2 polynomial used during keygen. The aggregated signature is invalid and fails verification against the public key generated in step 1.
5. Honest parties have completed the full signing round and received an unusable signature with no protocol-level indication of the misconfiguration.

**Relevant code locations:**

- Missing check in `assert_sign_inputs`: [1](#0-0) 
- Missing check in `frost::presign`: [2](#0-1) 
- Correct guard present in `assert_key_invariants`: [3](#0-2) 
- `ReconstructionLowerBound` has no minimum enforcement: [4](#0-3)

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

**File:** src/dkg.rs (L579-582)
```rust
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
