Looking at the codebase, I need to find an analog to the "missing zero/null check on a parameter assigned to a privileged variable" pattern. Let me examine the threshold validation asymmetry between keygen and signing.

The key finding is in `src/frost/mod.rs` (`assert_sign_inputs`) vs `src/dkg.rs` (`assert_key_invariants`):

- `assert_key_invariants` enforces `threshold >= 2` (lower bound) **and** `threshold <= participants.len()` (upper bound)
- `assert_sign_inputs` enforces **only** the upper bound (`threshold <= participants.len()`), with no lower bound check

---

### Title
Missing Lower-Bound Validation on `threshold` in FROST `assert_sign_inputs` Allows Signing Protocol Corruption — (File: `src/frost/mod.rs`)

### Summary
`assert_sign_inputs` in `src/frost/mod.rs` validates the `threshold` parameter only with an upper-bound check. It is missing the lower-bound check (`threshold >= 2`) that `assert_key_invariants` in `src/dkg.rs` enforces for keygen. A malicious or buggy library caller can pass `threshold=0` or `threshold=1` to any FROST signing function, causing the signing protocol to proceed with invalid Lagrange interpolation parameters and produce a corrupted, unusable signature output.

### Finding Description

`assert_key_invariants` in `src/dkg.rs` enforces a minimum threshold of 2: [1](#0-0) 

```rust
if threshold < 2 {
    return Err(InitializationError::ThresholdTooSmall { threshold, min: 2 });
}
```

By contrast, `assert_sign_inputs` in `src/frost/mod.rs` only checks the upper bound: [2](#0-1) 

```rust
// validate threshold
if threshold.value() > participants.len() {
    return Err(InitializationError::ThresholdTooLarge {
        threshold: threshold.value(),
        max: participants.len(),
    });
}
```

There is no corresponding `threshold < 2` guard. The `ReconstructionLowerBound` and `MaxMalicious` wrapper types in `src/thresholds.rs` accept any `usize`, including 0: [3](#0-2) 

So a caller can construct `ReconstructionLowerBound::from(1usize)` (or `0`) and pass it directly to any FROST signing entry point that calls `assert_sign_inputs`. The validation gate passes silently, and the signing protocol proceeds.

In FROST, the threshold governs Lagrange interpolation during share combination. With `threshold=1`, the coordinator computes a Lagrange coefficient of 1 for a single-participant set and combines only one share `s_i`. Because the DKG was performed with `threshold=2` (degree-1 polynomial), `s_i` is a share of the secret, not the secret itself. The combined value `s = s_i` does not equal `nonce + challenge * secret`, so the produced signature is cryptographically invalid and unusable by any verifier.

With `threshold=0`, Lagrange interpolation over an empty set causes arithmetic failure (division by zero or empty-product errors), aborting the protocol entirely.

### Impact Explanation
**High — Corruption of sign outputs so honest parties accept unusable cryptographic outputs.**

When a caller (malicious coordinator, misconfigured participant, or attacker-controlled library consumer) passes `threshold < 2` to a FROST signing function, the protocol runs to completion but produces a signature that fails verification. Honest parties who trust the output of the signing protocol receive an unusable signature. If the signing session is non-repeatable (e.g., presignature consumed, nonces discarded), the signing round is permanently wasted and cannot be retried without a new presign phase.

### Likelihood Explanation
**Medium.** The `ReconstructionLowerBound` type is a plain `usize` newtype with no constructor-level enforcement. Any library caller who assembles signing arguments programmatically (e.g., from a config file, a network message, or a coordinator-supplied parameter) can supply an out-of-range threshold. The asymmetry with `assert_key_invariants` means developers familiar with keygen validation may not realize signing lacks the same guard. A malicious coordinator controlling the threshold argument can trigger this on demand.

### Recommendation
Add the same lower-bound guard to `assert_sign_inputs` that `assert_key_invariants` already enforces:

```rust
// In src/frost/mod.rs, assert_sign_inputs, after the upper-bound check:
if threshold.value() < 2 {
    return Err(InitializationError::ThresholdTooSmall {
        threshold: threshold.value(),
        min: 2,
    });
}
```

Apply the same fix to the `threshold` validation in `src/ecdsa/ot_based_ecdsa/sign.rs` and `src/frost/mod.rs::presign`, which also lack a lower-bound check on the threshold parameter. [4](#0-3) 

### Proof of Concept

```rust
// Attacker-controlled call with threshold=1 on a 2-of-3 keygen output
let bad_threshold = ReconstructionLowerBound::from(1usize);

// assert_sign_inputs passes: 1 <= 3 (upper bound only), no lower bound check
let participants_list = assert_sign_inputs(
    &participants,   // 3 participants from a threshold=2 DKG
    bad_threshold,   // threshold=1 — passes validation silently
    me,
    coordinator,
).unwrap(); // <-- no error returned

// Signing proceeds; coordinator collects 1 share, computes Lagrange coeff=1
// s = s_i (a degree-1 share, not the reconstructed secret)
// Resulting signature fails verification against the DKG public key
```

The root cause is the missing `threshold.value() < 2` guard at [2](#0-1)  compared to the enforced guard at [1](#0-0) .

### Citations

**File:** src/dkg.rs (L579-582)
```rust
    // Step 1.1
    if threshold < 2 {
        return Err(InitializationError::ThresholdTooSmall { threshold, min: 2 });
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

**File:** src/thresholds.rs (L9-18)
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
```

**File:** src/ecdsa/ot_based_ecdsa/sign.rs (L57-63)
```rust
    // ensure number of participants during the signing phase is >= threshold
    if participants.len() < threshold {
        return Err(InitializationError::NotEnoughParticipantsForThreshold {
            threshold,
            participants: participants.len(),
        });
    }
```
