### Title
Missing Lower-Bound Threshold Validation in FROST Signing Allows Corrupted Signature Output - (File: src/frost/mod.rs)

---

### Summary

The `assert_sign_inputs` and `presign` functions in `src/frost/mod.rs` validate only the upper bound of the `threshold` parameter (ensuring it does not exceed the participant count), but never enforce the minimum threshold of 2 that the DKG and triple-generation layers explicitly require. A library caller or malicious coordinator can pass `threshold = 1` (or `threshold = 0`) to the FROST signing protocol. Because the Lagrange interpolation during signing uses the caller-supplied threshold to compute coefficients, a mismatch with the keygen threshold produces a cryptographically invalid signature that cannot be verified against the established public key, corrupting the signing output for all honest participants.

---

### Finding Description

The DKG layer and the OT-based triple generation both enforce `threshold >= 2` at initialization time:

- `validate_triple_inputs` in `src/ecdsa/ot_based_ecdsa/triples/generation.rs` (lines 699–703) returns `InitializationError::ThresholdTooSmall { threshold, min: 2 }` when `threshold_value < 2`.
- The DKG test harness at `src/dkg.rs` (line 755) confirms the same guard exists in `keygen` and `reshare`.

However, the shared FROST signing validation helper `assert_sign_inputs` in `src/frost/mod.rs` only checks the upper bound:

```rust
// validate threshold
if threshold.value() > participants.len() {
    return Err(InitializationError::ThresholdTooLarge { ... });
}
```

There is no corresponding lower-bound guard (`threshold.value() < 2`). The same omission exists in the `presign` function in the same file (line 72):

```rust
if args.threshold.value() > participants.len() {
    return Err(InitializationError::ThresholdTooLarge { ... });
}
```

`ReconstructionLowerBound` is a plain `usize` newtype with no invariant enforced at construction:

```rust
pub struct ReconstructionLowerBound(usize);
```

A caller can freely construct `ReconstructionLowerBound(1)` or `ReconstructionLowerBound(0)` and pass it to any FROST signing or presigning entry point. Both functions accept it without error.

---

### Impact Explanation

When `threshold = 1` is supplied to the FROST signing protocol, the Lagrange interpolation coefficients computed during signing are inconsistent with those used during key generation (which required `threshold >= 2`). The resulting partial signature shares, when aggregated, produce a final signature that fails verification against the established group public key. All honest participants complete the protocol and accept the output, but the signature is cryptographically unusable. This maps directly to:

> **High: Corruption of sign outputs so honest parties accept unusable cryptographic outputs.**

If `threshold = 0` is supplied, the Lagrange computation may encounter a zero-denominator or produce a degenerate result, causing a protocol abort or a nonsensical output — either way, signing is permanently broken for that session.

---

### Likelihood Explanation

The `assert_sign_inputs` function is a public API surface consumed by both the EdDSA and RedJubjub FROST signing paths. Any library caller — including an unprivileged application developer who misreads the API contract, or a malicious coordinator who deliberately supplies a low threshold to sabotage a signing session — can trigger this path. No special privileges, leaked keys, or cryptographic breaks are required. The `ReconstructionLowerBound` type provides no compile-time or runtime guard against values below 2.

---

### Recommendation

Add an explicit lower-bound check in `assert_sign_inputs` and in the `presign` function, mirroring the guard already present in `validate_triple_inputs`:

```rust
if threshold.value() < 2 {
    return Err(InitializationError::ThresholdTooSmall {
        threshold: threshold.value(),
        min: 2,
    });
}
```

This should be inserted immediately after the upper-bound check in both locations. Optionally, enforce the invariant at the `ReconstructionLowerBound` construction site so that invalid values cannot be represented at all.

---

### Proof of Concept

1. Run DKG with `threshold = 2` and `N = 3` participants, producing valid key shares.
2. Call the FROST EdDSA `sign` function (which internally calls `assert_sign_inputs`) with the same participants but `threshold = 1`.
3. Observe that `assert_sign_inputs` returns `Ok(participants)` — no error is raised.
4. The signing protocol proceeds; each participant computes their Lagrange coefficient as if only 1 share is needed, producing coefficients inconsistent with the keygen polynomial.
5. The aggregated signature fails `verify` against the public key established in step 1.
6. All honest participants have completed the protocol and consumed their nonce material, yet the output is unusable — signing is effectively denied for this session.

**Root cause location:**

`assert_sign_inputs`, missing lower-bound guard: [1](#0-0) 

`presign`, missing lower-bound guard: [2](#0-1) 

Contrast with the guard that IS present in triple generation: [3](#0-2) 

`ReconstructionLowerBound` — no minimum invariant enforced: [4](#0-3)

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

**File:** src/ecdsa/ot_based_ecdsa/triples/generation.rs (L699-704)
```rust
    if threshold_value < 2 {
        return Err(InitializationError::ThresholdTooSmall {
            threshold: threshold_value,
            min: 2,
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
