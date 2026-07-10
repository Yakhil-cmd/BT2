### Title
Missing Minimum Threshold Enforcement in FROST Presign and Sign Allows Threshold=1, Producing Unusable Signatures — (`src/frost/mod.rs`)

---

### Summary

The FROST presign (`presign`) and sign (`assert_sign_inputs`) functions in `src/frost/mod.rs` do not enforce a minimum threshold of 2, unlike the DKG functions which correctly reject `threshold < 2`. A library caller can pass `threshold=1` (or `threshold=0`) to these functions; the call is accepted without error, but the resulting signing output is cryptographically invalid and unusable.

---

### Finding Description

**Root cause — inconsistent minimum-threshold enforcement across protocol phases.**

`assert_key_invariants` in `src/dkg.rs` correctly enforces `threshold >= 2`: [1](#0-0) 

```rust
if threshold < 2 {
    return Err(InitializationError::ThresholdTooSmall { threshold, min: 2 });
}
```

The same check exists in `validate_triple_inputs` for OT-based ECDSA triple generation: [2](#0-1) 

However, the FROST `presign` function in `src/frost/mod.rs` only checks the upper bound: [3](#0-2) 

```rust
// validate threshold
if args.threshold.value() > participants.len() {
    return Err(InitializationError::ThresholdTooLarge { ... });
}
// ← no lower-bound check; threshold=1 or threshold=0 is silently accepted
```

Identically, `assert_sign_inputs` (called by every FROST sign entry-point such as `sign_v1`) only checks the upper bound: [4](#0-3) 

```rust
// validate threshold
if threshold.value() > participants.len() {
    return Err(InitializationError::ThresholdTooLarge { ... });
}
// ← no lower-bound check
```

`ReconstructionLowerBound` is a plain newtype with no invariant on its inner value: [5](#0-4) 

So `ReconstructionLowerBound::from(1usize)` (or `from(0)`) is a valid value that passes every FROST validation gate.

---

### Impact Explanation

**High — Corruption of sign outputs; honest parties accept unusable cryptographic outputs.**

In FROST, the threshold determines how many participants' signature shares are Lagrange-combined to reconstruct the group signature. When `threshold=1` is supplied:

- The coordinator selects only one participant (itself).
- The Lagrange coefficient collapses to 1, so the combined scalar is `z = nonce_i + secret_i · challenge`, where `secret_i` is a *share* of the secret key, not the full key.
- The resulting `(R, z)` pair is not a valid EdDSA/RedJubjub signature and fails verification against the master public key.

The library emits **no error** during this process. Honest callers receive a structurally well-formed but cryptographically invalid signature object, matching the allowed High impact: *"Corruption of … sign … outputs so honest parties accept … unusable cryptographic outputs."*

---

### Likelihood Explanation

**Low.** The attacker must be a library caller who deliberately (or accidentally) passes `threshold=1` to a FROST signing entry-point. Because the DKG phase correctly enforces `threshold >= 2`, an integrator who assumes the signing phase applies the same guard is the realistic victim of accidental misconfiguration. A malicious coordinator who controls the threshold argument could also trigger this deliberately to produce a signing session that always fails, permanently denying signing for honest participants.

---

### Recommendation

Add the same lower-bound guard that `assert_key_invariants` already applies, in both `presign` and `assert_sign_inputs` inside `src/frost/mod.rs`:

```rust
if threshold.value() < 2 {
    return Err(InitializationError::ThresholdTooSmall {
        threshold: threshold.value(),
        min: 2,
    });
}
```

This mirrors the existing pattern in `src/dkg.rs` (line 580) and `src/ecdsa/ot_based_ecdsa/triples/generation.rs` (line 699) and closes the inconsistency across all protocol phases.

---

### Proof of Concept

```rust
// 1. DKG with threshold=3 — correctly enforced, succeeds.
let keygen_out = keygen::<Ed25519Sha512>(&participants, me, 3usize, rng)?;

// 2. FROST presign with threshold=1 — missing lower-bound check, silently accepted.
let presign_out = presign(
    &participants,
    me,
    &PresignArguments {
        keygen_out: keygen_out.clone(),
        threshold: ReconstructionLowerBound::from(1usize), // ← accepted, no error
    },
    rng,
)?;

// 3. FROST sign with threshold=1 — assert_sign_inputs accepts it.
let sig_protocol = sign_v1(
    &participants,
    ReconstructionLowerBound::from(1usize), // ← accepted, no error
    coordinator,
    me,
    keygen_out,
    message,
    rng,
)?;

// 4. Protocol completes without error, but the resulting signature
//    fails EdDSA verification against the master public key —
//    an unusable cryptographic output delivered silently.
```

### Citations

**File:** src/dkg.rs (L579-582)
```rust
    // Step 1.1
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
