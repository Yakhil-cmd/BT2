### Title
Missing Lower-Bound Threshold Validation in FROST Presign/Sign Allows `threshold = 1`, Corrupting Signing Outputs — (File: `src/frost/mod.rs`)

---

### Summary
The FROST presign and sign entry points in `src/frost/mod.rs` omit the lower-bound check (`threshold >= 2`) that every other protocol entry point in the codebase enforces. A caller can supply `threshold = 1`, causing Lagrange interpolation during signing to reconstruct the wrong secret, producing an invalid and unusable signature. Honest participants complete the protocol and accept the corrupted output.

---

### Finding Description

Every other threshold-bearing entry point in the codebase enforces a minimum threshold of 2:

- `assert_key_invariants` in `src/dkg.rs` (lines 580–582):
  ```rust
  if threshold < 2 {
      return Err(InitializationError::ThresholdTooSmall { threshold, min: 2 });
  }
  ``` [1](#0-0) 

- `validate_triple_inputs` in `src/ecdsa/ot_based_ecdsa/triples/generation.rs` (lines 699–703):
  ```rust
  if threshold_value < 2 {
      return Err(InitializationError::ThresholdTooSmall { threshold: threshold_value, min: 2 });
  }
  ``` [2](#0-1) 

However, `presign()` and `assert_sign_inputs()` in `src/frost/mod.rs` only check the upper bound:

```rust
// validate threshold
if args.threshold.value() > participants.len() {
    return Err(InitializationError::ThresholdTooLarge { ... });
}
``` [3](#0-2) 

```rust
// validate threshold
if threshold.value() > participants.len() {
    return Err(InitializationError::ThresholdTooLarge { ... });
}
``` [4](#0-3) 

Neither function rejects `threshold = 1`. The `ReconstructionLowerBound` type itself imposes no minimum:

```rust
pub struct ReconstructionLowerBound(usize);
``` [5](#0-4) 

The `PresignArguments` struct exposes `threshold` as a plain caller-supplied field, separate from the `keygen_out` that was generated with `threshold >= 2`:

```rust
pub struct PresignArguments<C: Ciphersuite> {
    pub keygen_out: KeygenOutput<C>,
    pub threshold: ReconstructionLowerBound,
}
``` [6](#0-5) 

Because the key was generated with a degree-(threshold−1) polynomial where `threshold >= 2`, each participant's share lies on a degree-≥1 polynomial. When signing is invoked with `threshold = 1`, Lagrange interpolation uses only one share to reconstruct the constant term, yielding the wrong secret scalar. The aggregated signature is cryptographically invalid.

---

### Impact Explanation

Honest participants complete the FROST signing protocol and accept the output, but the resulting signature fails verification against the public key. This is a **corruption of sign outputs so honest parties accept unusable cryptographic outputs** — matching the High impact tier: *Corruption of DKG, reshare, refresh, presign, sign, or CKD outputs so honest parties accept inconsistent public keys, participant sets, transcripts, or unusable cryptographic outputs.*

Additionally, if a malicious coordinator repeatedly supplies `threshold = 1` to signing sessions, honest parties are permanently denied the ability to produce a usable signature — matching the High impact tier: *Permanent denial of signing for honest parties under valid protocol inputs.*

---

### Likelihood Explanation

The `presign` and `assert_sign_inputs` functions are public API entry points callable by any library user. The `threshold` field in `PresignArguments` is a plain `usize`-backed struct with no enforced minimum. A malicious coordinator or misconfigured caller can trivially pass `threshold = 1` without any prior privilege. The missing check is a single-line omission compared to the pattern used consistently in every other protocol entry point.

---

### Recommendation

Add the same lower-bound guard used in `assert_key_invariants` and `validate_triple_inputs` to both `presign` and `assert_sign_inputs` in `src/frost/mod.rs`:

```rust
// In presign():
if args.threshold.value() < 2 {
    return Err(InitializationError::ThresholdTooSmall {
        threshold: args.threshold.value(),
        min: 2,
    });
}

// In assert_sign_inputs():
if threshold.value() < 2 {
    return Err(InitializationError::ThresholdTooSmall {
        threshold: threshold.value(),
        min: 2,
    });
}
```

This mirrors the existing pattern in `src/dkg.rs` lines 580–582 and `src/ecdsa/ot_based_ecdsa/triples/generation.rs` lines 699–703. [1](#0-0) [2](#0-1) 

---

### Proof of Concept

1. Run DKG with `threshold = 2`, `N = 3` participants → produces valid shares on a degree-1 polynomial.
2. Call `presign(participants, me, &PresignArguments { keygen_out, threshold: 1.into() }, rng)` — accepted without error.
3. Call `assert_sign_inputs(participants, 1usize, me, coordinator)` — accepted without error.
4. Proceed with FROST signing using `threshold = 1`: only one partial signature is collected; Lagrange interpolation with a single point reconstructs the wrong scalar.
5. The aggregated signature fails `verify(public_key, message, signature)` — honest parties have completed the protocol and accepted a corrupted, unusable output.

### Citations

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

**File:** src/frost/mod.rs (L25-30)
```rust
pub struct PresignArguments<C: Ciphersuite> {
    /// The output of key generation, i.e. our share of the secret key, and the public key package.
    pub keygen_out: KeygenOutput<C>,
    /// The threshold for the scheme
    pub threshold: ReconstructionLowerBound,
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

**File:** src/thresholds.rs (L9-12)
```rust
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, From, Into,
)]
pub struct ReconstructionLowerBound(usize);
```
