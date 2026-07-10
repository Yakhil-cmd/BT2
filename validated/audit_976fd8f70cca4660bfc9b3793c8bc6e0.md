### Title
Missing Lower-Bound Validation on `threshold` in FROST Sign/Presign Entry Points - (File: `src/frost/mod.rs`)

### Summary
The keygen entry point enforces `threshold >= 2` via `assert_key_invariants`, but the FROST presign and sign entry points (`presign` and `assert_sign_inputs` in `src/frost/mod.rs`) only validate the upper bound (`threshold <= participants.len()`). A caller can supply `threshold = 1` to these functions, bypassing the minimum-threshold invariant that was enforced at key generation time.

### Finding Description
`assert_key_invariants` in `src/dkg.rs` enforces both bounds on the threshold:

```rust
// src/dkg.rs:573-582
if threshold > participants.len() {
    return Err(InitializationError::ThresholdTooLarge { ... });
}
if threshold < 2 {
    return Err(InitializationError::ThresholdTooSmall { threshold, min: 2 });
}
``` [1](#0-0) 

This function is called by every keygen and reshare entry point, so no key can be generated with `threshold < 2`.

However, the FROST `presign` function in `src/frost/mod.rs` only validates the upper bound:

```rust
// src/frost/mod.rs:72-77
if args.threshold.value() > participants.len() {
    return Err(InitializationError::ThresholdTooLarge { ... });
}
``` [2](#0-1) 

Likewise, `assert_sign_inputs` (the shared validation helper for EdDSA and RedJubjub sign) only validates the upper bound:

```rust
// src/frost/mod.rs:144-150
if threshold.value() > participants.len() {
    return Err(InitializationError::ThresholdTooLarge { ... });
}
``` [3](#0-2) 

The lower-bound check (`threshold >= 2`) is entirely absent from both signing-phase entry points. A caller may pass `threshold = 1` and the library will accept it without error.

The same gap exists in the OT-based ECDSA `sign` entry point, which validates `participants.len() >= threshold` but never `threshold >= 2`: [4](#0-3) 

### Impact Explanation
**High — Corruption of sign outputs so honest parties accept unusable cryptographic outputs.**

In FROST, the threshold governs the Lagrange interpolation coefficients used to combine per-participant signature shares. When `threshold = 1` is supplied at sign time while the key was generated with `threshold = 2`, the Lagrange coefficients computed over the participant identifiers are wrong (a degree-0 interpolation is used instead of degree-1). The aggregated signature is therefore cryptographically invalid and will fail verification. Honest participants who completed the protocol correctly will have produced and accepted an unusable output, constituting a corruption of the signing session.

### Likelihood Explanation
Any caller of the FROST presign or sign functions controls the `threshold` parameter directly — it is not derived from or cross-checked against the `KeygenOutput` struct (which stores only `public_key` and `private_share`, not the threshold). A malicious coordinator who orchestrates a signing session can supply `threshold = 1` to all honest participants, causing every participant to compute incorrect Lagrange coefficients and produce a corrupted, unverifiable signature. No special privilege beyond being a protocol participant is required.

### Recommendation
Add the same lower-bound check that `assert_key_invariants` applies to both `presign` and `assert_sign_inputs` in `src/frost/mod.rs`:

```diff
// src/frost/mod.rs – presign
 if args.threshold.value() > participants.len() {
     return Err(InitializationError::ThresholdTooLarge { ... });
 }
+if args.threshold.value() < 2 {
+    return Err(InitializationError::ThresholdTooSmall {
+        threshold: args.threshold.value(),
+        min: 2,
+    });
+}

// src/frost/mod.rs – assert_sign_inputs
 if threshold.value() > participants.len() {
     return Err(InitializationError::ThresholdTooLarge { ... });
 }
+if threshold.value() < 2 {
+    return Err(InitializationError::ThresholdTooSmall {
+        threshold: threshold.value(),
+        min: 2,
+    });
+}
```

Apply the same fix to `sign` in `src/ecdsa/ot_based_ecdsa/sign.rs`. [5](#0-4) 

### Proof of Concept

```rust
// Pseudocode demonstrating the bypass
let keygen_output = keygen(&participants, me, /*threshold=*/ 2, rng)?;
// keygen enforces threshold >= 2 — OK

let presign_args = PresignArguments {
    keygen_out: keygen_output,
    threshold: ReconstructionLowerBound::from(1usize), // threshold = 1
};

// presign accepts threshold = 1 without error:
let presign_protocol = presign(&participants, me, &presign_args, rng)?;
// No ThresholdTooSmall error is returned.

// assert_sign_inputs also accepts threshold = 1:
let participant_list = assert_sign_inputs(&participants, 1usize, me, coordinator)?;
// No ThresholdTooSmall error is returned.
// Signing proceeds with wrong Lagrange coefficients → corrupted, unverifiable signature.
```

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
