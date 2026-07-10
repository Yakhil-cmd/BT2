### Title
Missing Lower-Bound Threshold Validation in FROST Signing and Presigning Corrupts Protocol Output - (File: src/frost/mod.rs)

### Summary
The `assert_sign_inputs` and `presign` functions in `src/frost/mod.rs` omit the `threshold >= 2` lower-bound check that is consistently enforced in every other threshold-bearing entry point in the codebase (`assert_key_invariants`, `validate_triple_inputs`). A malicious caller or coordinator who controls the `threshold` argument can pass `threshold = 1` into FROST signing or presigning. The protocol then proceeds with Lagrange interpolation coefficients computed for a degree-0 polynomial, which are inconsistent with the shares produced during DKG (which always enforces `threshold >= 2`). The result is a corrupted, unusable signature output accepted by all honest participants.

### Finding Description
**Root cause — missing check in `assert_sign_inputs`:**

`assert_sign_inputs` in `src/frost/mod.rs` validates the signing inputs for both EdDSA and RedJubjub FROST signing. It checks the upper bound (`threshold > participants.len()`) but never checks the lower bound:

```rust
// validate threshold
if threshold.value() > participants.len() {
    return Err(InitializationError::ThresholdTooLarge { ... });
}
// ← NO lower-bound check: threshold >= 2 is absent
``` [1](#0-0) 

The same omission exists in the FROST `presign` entry point: [2](#0-1) 

**Contrast with every other entry point:**

`assert_key_invariants` (DKG) explicitly rejects `threshold < 2`:

```rust
if threshold < 2 {
    return Err(InitializationError::ThresholdTooSmall { threshold, min: 2 });
}
``` [3](#0-2) 

`validate_triple_inputs` (OT-based ECDSA triple generation) does the same: [4](#0-3) 

The `ThresholdTooSmall` error variant exists precisely for this purpose, confirming the type `ReconstructionLowerBound` does not enforce a minimum of 2 at the type level — the runtime check is the only guard: [5](#0-4) 

**Exploit path:**

1. DKG is run honestly with `threshold = 2`, producing shares for all participants.
2. A malicious coordinator calls the FROST EdDSA or RedJubjub `sign` function (which calls `assert_sign_inputs`) with `threshold = 1`.
3. `assert_sign_inputs` passes all checks — `1 <= participants.len()` and no lower-bound check exists.
4. The signing protocol proceeds. Each participant computes their signature share using Lagrange coefficients derived for a degree-0 polynomial (threshold=1), which are inconsistent with the degree-1 shares produced during DKG.
5. The coordinator aggregates the shares. The resulting signature is cryptographically invalid and unusable.
6. All honest participants have committed their nonces and shares; the session is consumed and cannot be retried with the same presignature.

### Impact Explanation
**High — Corruption of signing outputs so honest parties produce unusable cryptographic outputs.**

Every honest participant executes the protocol to completion and accepts the (invalid) aggregated signature as the session result. The signing session is permanently wasted. If presignatures are consumed in the process, the denial extends to those presignature slots as well. The corrupted output cannot be distinguished from a valid one by participants who do not independently verify the final signature against the public key.

### Likelihood Explanation
The `threshold` parameter is fully caller-controlled at the public API boundary. Any party that initiates a signing session — including a malicious coordinator, which is an explicitly documented attacker profile — can supply `threshold = 1` without any privilege beyond the ability to call the signing function. No cryptographic break, key leakage, or external assumption is required. The missing check is a single missing `if` branch, making accidental misuse equally plausible.

### Recommendation
Add the same lower-bound guard that exists in `assert_key_invariants` and `validate_triple_inputs` to both `assert_sign_inputs` and the FROST `presign` function:

```rust
if threshold.value() < 2 {
    return Err(InitializationError::ThresholdTooSmall {
        threshold: threshold.value(),
        min: 2,
    });
}
```

This should be inserted immediately after the upper-bound check in both locations:
- `assert_sign_inputs` in `src/frost/mod.rs` (after line 150)
- `presign` in `src/frost/mod.rs` (after line 76)

### Proof of Concept

```rust
// DKG was run with threshold = 2, producing valid shares.
// Malicious coordinator now calls sign with threshold = 1:
let participants = vec![p1, p2, p3];
let result = frost::eddsa::sign::sign(
    &participants,
    coordinator,
    1u8,          // ← threshold = 1, passes assert_sign_inputs unchecked
    me,
    public_key,
    presign_output,
    msg_hash,
);
// Returns Ok(...) — no error is raised.
// Protocol runs to completion; coordinator aggregates shares computed
// with Lagrange coefficients for threshold=1 (λ_i = 1 for a single point),
// inconsistent with the degree-1 shares from DKG.
// Final signature fails external verification.
```

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

**File:** src/ecdsa/ot_based_ecdsa/triples/generation.rs (L699-704)
```rust
    if threshold_value < 2 {
        return Err(InitializationError::ThresholdTooSmall {
            threshold: threshold_value,
            min: 2,
        });
    }
```

**File:** src/errors.rs (L140-141)
```rust
    #[error("threshold {threshold} is too small, it must be at least {min}")]
    ThresholdTooSmall { threshold: usize, min: usize },
```
