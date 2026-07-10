### Title
Missing Lower-Bound Validation on `threshold` in `assert_sign_inputs` Allows Threshold=1 FROST Signing — (File: src/frost/mod.rs)

### Summary
`assert_sign_inputs` and `presign` in `src/frost/mod.rs` validate the upper bound of the `threshold` parameter (`threshold > participants.len()`) but omit the lower-bound check (`threshold >= 2`) that is explicitly enforced in `assert_key_invariants` in `src/dkg.rs`. A malicious caller or coordinator can supply `threshold = 1`, bypassing the threshold security property and causing the FROST signing protocol to produce a cryptographically invalid/corrupted signature output that honest participants cannot use.

---

### Finding Description

`assert_key_invariants` in `src/dkg.rs` enforces both bounds on `threshold`:

```rust
// src/dkg.rs lines 573–582
if threshold > participants.len() {
    return Err(InitializationError::ThresholdTooLarge { ... });
}
if threshold < 2 {
    return Err(InitializationError::ThresholdTooSmall { threshold, min: 2 });
}
``` [1](#0-0) 

In contrast, `assert_sign_inputs` in `src/frost/mod.rs` only checks the upper bound:

```rust
// src/frost/mod.rs lines 144–150
// validate threshold
if threshold.value() > participants.len() {
    return Err(InitializationError::ThresholdTooLarge {
        threshold: threshold.value(),
        max: participants.len(),
    });
}
``` [2](#0-1) 

The lower-bound check (`threshold < 2`) is entirely absent. The same omission exists in the `presign` function in the same file:

```rust
// src/frost/mod.rs lines 71–77
if args.threshold.value() > participants.len() {
    return Err(InitializationError::ThresholdTooLarge {
        threshold: args.threshold.into(),
        max: participants.len(),
    });
}
``` [3](#0-2) 

This is the direct analog of the external report's bug: the upper-bound check on `participants.len()` (already validated separately) is present, while the lower-bound check on `threshold` itself is missing — exactly the "wrong/incomplete variable checked" pattern.

---

### Impact Explanation

In FROST, the signing share `x_i` held by participant `i` is an evaluation of a degree-`(threshold−1)` polynomial at `i`'s identifier. The secret key `x = f(0)` is only recoverable with at least `threshold` shares via Lagrange interpolation.

When `threshold = 1` is accepted by `assert_sign_inputs`:
- Only one participant is required to produce a signing output.
- The Lagrange coefficient for that single participant collapses to `λ_i = 1`.
- The signature share becomes `z_i = nonce_i + 1 · x_i · challenge`, where `x_i ≠ x` (the actual secret key, since DKG was run with `threshold ≥ 2`).
- The aggregated signature `(R, z)` is cryptographically invalid and cannot be verified against the master public key.

Honest participants who contributed nonces and signature shares receive a corrupted, unusable output. This matches the **High** impact: *Corruption of sign outputs so honest parties accept unusable cryptographic outputs*.

---

### Likelihood Explanation

`assert_sign_inputs` is a public library function. Any unprivileged library caller or malicious coordinator invoking the EdDSA/FROST signing path can supply an arbitrary `threshold` value. No special privilege or key material is required to trigger this path. The `ReconstructionLowerBound` wrapper type imposes no minimum value constraint:

```rust
// src/thresholds.rs lines 9–13
pub struct ReconstructionLowerBound(usize);
impl ReconstructionLowerBound {
    pub fn value(self) -> usize { self.0 }
}
``` [4](#0-3) 

Any `usize` (including 0 or 1) converts into `ReconstructionLowerBound` via the derived `From` impl, so the caller faces no barrier.

---

### Recommendation

Add the same lower-bound guard present in `assert_key_invariants` to both `assert_sign_inputs` and `presign` in `src/frost/mod.rs`:

```rust
if threshold.value() < 2 {
    return Err(InitializationError::ThresholdTooSmall {
        threshold: threshold.value(),
        min: 2,
    });
}
```

This mirrors the existing check at `src/dkg.rs` lines 580–582 and closes the inconsistency. [5](#0-4) 

---

### Proof of Concept

1. Run DKG normally with `threshold = 2`, producing valid key shares for participants `[P1, P2, P3]`.
2. Call `assert_sign_inputs([P1, P2, P3], threshold=1, me=P1, coordinator=P1)` — this succeeds without error.
3. Proceed with FROST signing using `threshold = 1`; only `P1` participates.
4. `P1`'s Lagrange coefficient is `λ_1 = 1`; signature share `z_1 = nonce_1 + x_1 · challenge`.
5. The coordinator aggregates `z = z_1` and outputs signature `(R, z)`.
6. Verification against the master public key fails — the output is a corrupted, unusable signature, and honest participants `P2`, `P3` have had their protocol participation wasted.

### Citations

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
