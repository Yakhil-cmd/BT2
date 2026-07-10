### Title
Missing Lower-Bound Threshold Validation in FROST Signing and Presigning Allows Threshold-1 Protocol Execution — (`src/frost/mod.rs`)

---

### Summary

`assert_sign_inputs` and `presign` in `src/frost/mod.rs` validate that the caller-supplied `threshold` is not *too large*, but never check that it is at least `2`. A caller can pass `threshold = 1` (or even `0`) to the FROST EdDSA / RedJubjub signing and presigning entry points. Because the key was generated with `threshold ≥ 2`, running the signing protocol with `threshold = 1` causes Lagrange interpolation to use a single share, producing a cryptographically invalid / unusable signature and permanently denying signing for honest parties.

---

### Finding Description

`src/dkg.rs::assert_key_invariants` enforces a strict lower bound at key-generation time:

```rust
// src/dkg.rs  line 580
if threshold < 2 {
    return Err(InitializationError::ThresholdTooSmall { threshold, min: 2 });
}
```

The analogous guard is **absent** in both FROST signing entry points:

**`presign` in `src/frost/mod.rs` (lines 72–77):**
```rust
// validate threshold
if args.threshold.value() > participants.len() {
    return Err(InitializationError::ThresholdTooLarge { ... });
}
// ← no lower-bound check; threshold = 1 or 0 passes silently
```

**`assert_sign_inputs` in `src/frost/mod.rs` (lines 144–150):**
```rust
// validate threshold
if threshold.value() > participants.len() {
    return Err(InitializationError::ThresholdTooLarge { ... });
}
// ← same omission; called by eddsa/sign.rs and redjubjub/sign.rs
```

`ReconstructionLowerBound` is a plain `usize` newtype with no internal invariant:

```rust
// src/thresholds.rs  lines 9–24
pub struct ReconstructionLowerBound(usize);
impl ReconstructionLowerBound {
    pub fn value(self) -> usize { self.0 }
}
```

Any value including `0` or `1` is accepted.

---

### Impact Explanation

FROST signing uses the supplied `threshold` to select the set of Lagrange coefficients for share reconstruction. When `threshold = 1` is passed but the key was generated with `threshold = 2`, the protocol computes each participant's signature share using a single-point Lagrange coefficient (trivially `1`), which does **not** reconstruct the correct aggregate signing key. The resulting signature fails verification against the public key produced during DKG. Honest participants who complete the protocol receive an unusable, invalid signature — permanently denying signing for that presignature / nonce pair.

**Mapped impact:** *High — Corruption of sign/presign outputs so honest parties accept unusable cryptographic outputs.*

---

### Likelihood Explanation

The `threshold` parameter is supplied directly by the library caller (application layer or coordinator) at signing time. No cryptographic material is required to trigger this path — only the ability to call `presign` or the signing entry points with an arbitrary `ReconstructionLowerBound`. A malicious coordinator or a buggy application that passes `threshold = 1` will silently proceed past all validation and corrupt the signing round for all honest participants.

---

### Recommendation

Add the same lower-bound guard that `assert_key_invariants` already enforces, in both `presign` and `assert_sign_inputs`:

```rust
if threshold.value() < 2 {
    return Err(InitializationError::ThresholdTooSmall {
        threshold: threshold.value(),
        min: 2,
    });
}
```

This mirrors the existing check in `src/dkg.rs` at line 580 and closes the inconsistency between key-generation and signing validation.

---

### Proof of Concept

1. Run DKG with `participants = [A, B, C]`, `threshold = 2` — succeeds, produces key shares.
2. Call `presign` (or the FROST `sign` entry point via `assert_sign_inputs`) with the same participants but `threshold = 1`.
3. Both `presign` and `assert_sign_inputs` pass all validation checks (1 ≤ 3, no duplicate, self present, coordinator present).
4. The signing protocol executes with Lagrange coefficients computed for a 1-participant reconstruction set.
5. The produced signature fails `sig.verify(&public_key, &msg_hash)` — the signing output is permanently unusable.

Relevant code locations: [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3)

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
