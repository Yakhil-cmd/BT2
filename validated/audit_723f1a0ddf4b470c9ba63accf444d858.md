### Title
Missing Lower-Bound Threshold Validation in FROST Signing Allows Corrupted Signing Outputs — (`File: src/frost/mod.rs`)

---

### Summary

The FROST signing validation functions (`assert_sign_inputs` and `presign`) in `src/frost/mod.rs` accept a threshold value of 1 (or 0), which is explicitly forbidden by the protocol specification. Every other entry point in the codebase that accepts a threshold enforces `threshold >= 2`, but the FROST signing path omits this lower-bound check. A malicious coordinator or caller can supply `threshold = 1` to the signing protocol, causing it to proceed with a cryptographically invalid threshold and produce unusable signatures.

---

### Finding Description

The protocol documentation (`docs/dkg.md`, line 50) states:

> Each P_i asserts that **1 < threshold < N**.

The DKG entry point enforces this:

```rust
// src/dkg.rs, assert_key_invariants
if threshold < 2 {
    return Err(InitializationError::ThresholdTooSmall { threshold, min: 2 });
}
```

The ECDSA triple-generation entry point also enforces this:

```rust
// src/ecdsa/ot_based_ecdsa/triples/generation.rs, validate_triple_inputs
if threshold_value < 2 {
    return Err(InitializationError::ThresholdTooSmall {
        threshold: threshold_value,
        min: 2,
    });
}
```

However, the two FROST signing entry points perform **no lower-bound check**:

**`presign` (lines 44–88, `src/frost/mod.rs`):**
```rust
// validate threshold
if args.threshold.value() > participants.len() {
    return Err(InitializationError::ThresholdTooLarge { ... });
}
// ← no check that args.threshold.value() >= 2
```

**`assert_sign_inputs` (lines 120–160, `src/frost/mod.rs`):**
```rust
// validate threshold
if threshold.value() > participants.len() {
    return Err(InitializationError::ThresholdTooLarge { ... });
}
// ← no check that threshold.value() >= 2
```

`ReconstructionLowerBound` is a plain `usize` newtype with no internal invariant enforcing a minimum value, so `ReconstructionLowerBound(1)` or `ReconstructionLowerBound(0)` are freely constructible by any caller.

---

### Impact Explanation

When `threshold = 1` is accepted by the FROST signing path, the Lagrange interpolation uses only a single participant's share `f(i)` as if it were the secret key `f(0)`. Because the key was generated with `threshold >= 2` (a degree-≥1 polynomial), `f(i) ≠ f(0)` in general. The aggregated FROST signature is therefore cryptographically invalid and will fail verification. Honest parties who complete the protocol receive an unusable output — a corrupted signing result — with no indication that the threshold parameter was invalid.

This maps to: **High — Corruption of sign outputs so honest parties accept unusable cryptographic outputs.**

---

### Likelihood Explanation

The `assert_sign_inputs` function is a public API surface callable by any library user, including a malicious coordinator. The `ReconstructionLowerBound` type imposes no minimum, so passing `1.into()` requires no special privilege or knowledge. The missing check is a straightforward omission compared to the identical check present in every other threshold-accepting function in the codebase.

---

### Recommendation

Add the same lower-bound guard that `assert_key_invariants` and `validate_triple_inputs` already use, in both `presign` and `assert_sign_inputs`:

```rust
if threshold.value() < 2 {
    return Err(InitializationError::ThresholdTooSmall {
        threshold: threshold.value(),
        min: 2,
    });
}
```

Alternatively, encode the invariant directly in `ReconstructionLowerBound` by making its constructor return an error for values below 2, so the constraint is enforced at the type level rather than repeated at every call site.

---

### Proof of Concept

1. A coordinator constructs `PresignArguments { keygen_out: <valid keygen output with threshold=2>, threshold: ReconstructionLowerBound(1) }`.
2. The coordinator calls `presign(participants, me, &args, rng)`.
3. The upper-bound check (`1 > participants.len()`) passes for any group of ≥ 2 participants.
4. No lower-bound check fires; the protocol proceeds with `threshold = 1`.
5. The FROST aggregation uses Lagrange coefficients computed for a 1-of-N scheme over shares that were generated for a 2-of-N scheme, producing a signature `z = r_i + f(i)·c` instead of the required `z = r + f(0)·c`.
6. The resulting signature fails verification against the public key, leaving honest parties with an unusable output.

**Relevant code locations:**

- Missing lower-bound check in `presign`: [1](#0-0) 
- Missing lower-bound check in `assert_sign_inputs`: [2](#0-1) 
- Correct lower-bound check present in DKG: [3](#0-2) 
- Correct lower-bound check present in triple generation: [4](#0-3) 
- `ReconstructionLowerBound` has no minimum invariant: [5](#0-4) 
- Protocol spec requiring `1 < threshold < N`: [6](#0-5)

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

**File:** src/dkg.rs (L580-582)
```rust
    if threshold < 2 {
        return Err(InitializationError::ThresholdTooSmall { threshold, min: 2 });
    }
```

**File:** src/ecdsa/ot_based_ecdsa/triples/generation.rs (L699-703)
```rust
    if threshold_value < 2 {
        return Err(InitializationError::ThresholdTooSmall {
            threshold: threshold_value,
            min: 2,
        });
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

**File:** docs/dkg.md (L50-50)
```markdown
1.1 Each $P_i$ asserts that $1 < \mathsf{threshold} < N$.
```
