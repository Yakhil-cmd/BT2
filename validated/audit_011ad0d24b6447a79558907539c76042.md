### Title
Missing Minimum Threshold Validation in FROST `assert_sign_inputs` Allows Signing with Threshold=1, Producing Unusable Signatures - (File: src/frost/mod.rs)

### Summary
`assert_sign_inputs` in `src/frost/mod.rs` validates the upper bound of the `threshold` parameter (must not exceed participant count) but omits the lower-bound check (`threshold >= 2`) that is correctly enforced in `assert_key_invariants` in `src/dkg.rs`. A malicious coordinator can invoke the FROST signing protocol with `threshold = 1`, causing the Lagrange aggregation to reconstruct only a single participant's share rather than the actual group secret, producing a cryptographically invalid signature that honest participants cannot use.

### Finding Description

`assert_key_invariants` in `src/dkg.rs` enforces both bounds on `threshold`:

```rust
if threshold > participants.len() {
    return Err(InitializationError::ThresholdTooLarge { ... });
}
if threshold < 2 {
    return Err(InitializationError::ThresholdTooSmall { threshold, min: 2 });
}
``` [1](#0-0) 

`assert_sign_inputs` in `src/frost/mod.rs` only enforces the upper bound:

```rust
// validate threshold
if threshold.value() > participants.len() {
    return Err(InitializationError::ThresholdTooLarge { ... });
}
// ← no lower-bound check; threshold = 1 passes silently
``` [2](#0-1) 

The same omission exists in `frost::presign`:

```rust
// validate threshold
if args.threshold.value() > participants.len() {
    return Err(InitializationError::ThresholdTooLarge { ... });
}
// ← no lower-bound check
``` [3](#0-2) 

`ReconstructionLowerBound` is a plain `usize` wrapper with no minimum enforced at the type level, so the value `1` is accepted without error. [4](#0-3) 

### Impact Explanation

In FROST, the aggregation step uses Lagrange interpolation over the set of contributing participants. When `threshold = 1`, only one participant's partial signature is required. The Lagrange coefficient for a singleton set is `1`, so the "reconstructed" scalar is simply that participant's signing share `x_i`, not the actual group secret. The resulting aggregated signature fails verification against the public key. Honest participants who contributed their partial signatures receive an unusable cryptographic output — the signing round is wasted and must be restarted.

**Impact: High** — Corruption of sign outputs so honest parties accept unusable cryptographic outputs, matching the allowed scope.

### Likelihood Explanation

The coordinator role in FROST is responsible for initiating signing and aggregating partial signatures. A malicious coordinator (a participant who controls the signing invocation) can trivially pass `threshold = 1` to `assert_sign_inputs`. The check passes, the protocol runs to completion, and the coordinator outputs an invalid signature. No cryptographic break or external compromise is required — only control of the `threshold` argument at the call site.

### Recommendation

Add the same lower-bound guard that exists in `assert_key_invariants` to both `assert_sign_inputs` and `frost::presign`:

```rust
if threshold.value() < 2 {
    return Err(InitializationError::ThresholdTooSmall {
        threshold: threshold.value(),
        min: 2,
    });
}
```

This mirrors the existing check at `src/dkg.rs:580-582` and closes the inconsistency between the keygen and signing validation paths. [5](#0-4) 

### Proof of Concept

1. A malicious coordinator constructs a valid FROST signing session with `n = 3` participants (keygen was done with `threshold = 2`).
2. The coordinator calls the FROST `sign` function passing `threshold = 1` instead of `2`.
3. `assert_sign_inputs` checks `1 > 3` → false, so no error is returned.
4. The signing protocol proceeds; the coordinator collects only 1 partial signature.
5. Lagrange interpolation over a singleton set yields `lambda_i = 1`, so the aggregated scalar is `x_i` (the single participant's share), not the group secret.
6. The output signature fails `Signature::verify` against the public key.
7. All honest participants have expended their nonce material for this round and cannot reuse it; the signing round is permanently lost.

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
