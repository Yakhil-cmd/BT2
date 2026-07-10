### Title
Missing Minimum Threshold Validation in FROST Signing Allows Signing Output Corruption - (File: src/frost/mod.rs)

### Summary
The `assert_sign_inputs` function and `presign` function in `src/frost/mod.rs` validate the threshold parameter for FROST signing and presigning but only enforce an upper bound (`threshold <= participants.len()`). Neither enforces a minimum threshold of 2. This is directly inconsistent with every other threshold-validation site in the codebase. A malicious coordinator or any participant who controls the threshold argument can supply `threshold = 1`, causing the FROST signing protocol to execute with a cryptographically insufficient threshold, producing an unusable signature that honest parties accept as output but that cannot be verified against the public key.

---

### Finding Description

**Root cause — missing lower-bound check in `assert_sign_inputs` and `presign`:**

`src/frost/mod.rs` lines 144–150 (`assert_sign_inputs`):
```rust
// validate threshold
if threshold.value() > participants.len() {
    return Err(InitializationError::ThresholdTooLarge {
        threshold: threshold.value(),
        max: participants.len(),
    });
}
``` [1](#0-0) 

`src/frost/mod.rs` lines 71–77 (`presign`):
```rust
// validate threshold
if args.threshold.value() > participants.len() {
    return Err(InitializationError::ThresholdTooLarge {
        threshold: args.threshold.into(),
        max: participants.len(),
    });
}
``` [2](#0-1) 

Neither function contains a check equivalent to `threshold < 2`. The `ReconstructionLowerBound` wrapper type imposes no minimum at the type level, so `ReconstructionLowerBound(1)` or `ReconstructionLowerBound(0)` are accepted silently. [3](#0-2) 

**Contrast with every other validation site in the codebase:**

`src/dkg.rs` `assert_key_invariants` (called for every DKG, refresh, and reshare):
```rust
if threshold < 2 {
    return Err(InitializationError::ThresholdTooSmall { threshold, min: 2 });
}
``` [4](#0-3) 

`src/ecdsa/ot_based_ecdsa/triples/generation.rs` `validate_triple_inputs`:
```rust
if threshold_value < 2 {
    return Err(InitializationError::ThresholdTooSmall {
        threshold: threshold_value,
        min: 2,
    });
}
``` [5](#0-4) 

The DKG path correctly prevents key generation with `threshold = 1`. However, the FROST signing path has no such guard. Because `assert_sign_inputs` is the public entry-point validation for FROST signing (called by the `eddsa` and `redjubjub` submodules declared in `src/frost/mod.rs`), any caller who controls the threshold argument bypasses the minimum-threshold invariant entirely. [6](#0-5) 

**Protocol consequence:**

In FROST (Schnorr threshold signing), the threshold governs Lagrange interpolation of partial signatures. If `threshold = 1` is supplied at signing time while the key was generated with `threshold = 2` (the minimum enforced by DKG), the Lagrange coefficients used to aggregate partial signatures are computed over a single evaluation point. The interpolated aggregate scalar is therefore wrong relative to the secret key polynomial, and the resulting `(R, z)` pair fails verification against the public key. The signing protocol itself completes without returning an error — honest parties receive and accept the output — but the signature is cryptographically invalid.

---

### Impact Explanation

**Impact: High — Corruption of sign outputs so honest parties accept unusable cryptographic outputs.**

A malicious coordinator (who is a required participant per `assert_sign_inputs` line 153) calls the FROST signing function with `threshold = 1`. The protocol runs to completion. Every honest participant receives a well-formed `Signature` struct. No in-protocol error is raised. However, the signature does not verify against the group public key. Any downstream consumer (smart contract, validator, TEE application) that relies on the signature will reject it, permanently blocking the operation the signing was meant to authorize. Because the presignature nonces are consumed in the process, the presign output cannot be reused; a fresh presign and sign round is required, which the same malicious coordinator can sabotage again with the same technique.

---

### Likelihood Explanation

The coordinator role is explicitly required to be a member of the participant list (enforced at line 153 of `assert_sign_inputs`). In a realistic deployment, the coordinator is one of the threshold participants — a role that any participant in the signing group can occupy. No external privilege or key material is needed beyond being a legitimate signing participant. The attack requires only passing an integer `1` instead of the correct threshold value. There is no cryptographic barrier and no runtime check that catches it. [7](#0-6) 

---

### Recommendation

Add the same lower-bound guard that exists in `assert_key_invariants` and `validate_triple_inputs` to both `assert_sign_inputs` and `presign` in `src/frost/mod.rs`:

```rust
if threshold.value() < 2 {
    return Err(InitializationError::ThresholdTooSmall {
        threshold: threshold.value(),
        min: 2,
    });
}
```

This should be inserted immediately after the `threshold.into()` conversion in both functions, before any other threshold comparison, mirroring the pattern already established in `src/dkg.rs` line 580 and `src/ecdsa/ot_based_ecdsa/triples/generation.rs` line 699.

---

### Proof of Concept

1. Run DKG with participants `[P1, P2, P3]` and `threshold = 2`. This succeeds because `assert_key_invariants` enforces `threshold >= 2`.
2. Call the FROST signing entry-point (e.g., `eddsa::sign` or `redjubjub::sign`) with the same participants and `threshold = 1`.
3. `assert_sign_inputs` checks `1 > 3` → false; no error is returned. The protocol initializes.
4. The signing protocol runs. With `threshold = 1`, Lagrange interpolation uses a single evaluation point; the aggregated scalar `z` is computed incorrectly relative to the degree-1 secret polynomial established during DKG.
5. All honest participants receive a `Signature { R, z }` and return `Ok(signature)`.
6. Calling `VerifyingKey::verify(public_key, message, &signature)` returns `Err` — the signature is invalid.
7. The presign nonces are consumed and cannot be reused. The malicious coordinator can repeat this on every signing attempt, permanently denying valid signatures to honest parties.

### Citations

**File:** src/frost/mod.rs (L21-22)
```rust
pub mod eddsa;
pub mod redjubjub;
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

**File:** src/frost/mod.rs (L152-158)
```rust
    // ensure the coordinator is a participant
    if !participants.contains(coordinator) {
        return Err(InitializationError::MissingParticipant {
            role: "coordinator",
            participant: coordinator,
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

**File:** src/dkg.rs (L580-582)
```rust
    if threshold < 2 {
        return Err(InitializationError::ThresholdTooSmall { threshold, min: 2 });
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
