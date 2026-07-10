### Title
Missing Lower-Bound Threshold Validation in FROST `presign` and `assert_sign_inputs` Allows Single-Participant Signing - (File: src/frost/mod.rs)

---

### Summary

The `presign` and `assert_sign_inputs` functions in `src/frost/mod.rs` validate that the threshold does not exceed the participant count, but omit the symmetric lower-bound check (`threshold >= 2`). Every other analogous entry point in the codebase enforces both bounds. A caller supplying `threshold = 1` bypasses the multi-party requirement, allowing a single participant to reconstruct the aggregate signing key and produce a valid threshold signature unilaterally.

---

### Finding Description

In `src/frost/mod.rs`, both public entry points perform only an upper-bound threshold check:

**`presign` (line 72–77):** [1](#0-0) 

**`assert_sign_inputs` (line 145–150):** [2](#0-1) 

Neither function checks `threshold.value() < 2`. Compare this to `assert_key_invariants` in `src/dkg.rs`, which correctly enforces both bounds: [3](#0-2) 

And `validate_triple_inputs` in the OT-based ECDSA triple generation, which also enforces both bounds: [4](#0-3) 

The `ReconstructionLowerBound` type is a plain `usize` wrapper with no internal invariant preventing a value of 1 or 0: [5](#0-4) 

With `threshold = 1`, Lagrange interpolation in the FROST signing phase requires only a single participant's share to reconstruct the aggregate secret. The `do_presign` inner function does not receive the threshold at all and proceeds unconditionally: [6](#0-5) 

---

### Impact Explanation

**Critical — Unauthorized creation of a valid threshold signature.**

When `threshold = 1` is supplied:

1. `presign` passes all guards and produces a valid `PresignOutput` containing nonces and commitment maps for all participants.
2. The sign function (called via `assert_sign_inputs`) proceeds with `threshold = 1`. Lagrange interpolation at evaluation point 0 with a single share yields a coefficient of 1, meaning one participant's signing share alone reconstructs the full aggregate secret.
3. A single participant — or a malicious coordinator who controls one share — can compute a complete, cryptographically valid FROST signature over an arbitrary message without the cooperation of any other party.

This directly violates the threshold security guarantee: the scheme was keyed with threshold ≥ 2 (enforced by DKG), but signing accepts threshold = 1, collapsing the multi-party requirement to a single point of compromise.

---

### Likelihood Explanation

**Medium.** The `presign` and `assert_sign_inputs` functions are public library API. Any caller — including a malicious coordinator orchestrating a signing session — can supply an arbitrary `threshold` value. The DKG output does not embed the threshold used during key generation in a way that is re-validated at signing time, so there is no downstream check that would catch the mismatch. A malicious coordinator who controls one share and can invoke the signing API with `threshold = 1` can exploit this without any cryptographic break.

---

### Recommendation

Add the same lower-bound guard present in `assert_key_invariants` and `validate_triple_inputs` to both `presign` and `assert_sign_inputs`:

```rust
if threshold.value() < 2 {
    return Err(InitializationError::ThresholdTooSmall {
        threshold: threshold.value(),
        min: 2,
    });
}
```

This should be inserted immediately after converting the threshold, before any other checks, mirroring the pattern in `src/dkg.rs` lines 580–582.

---

### Proof of Concept

1. Run DKG with 3 participants and `threshold = 2` (enforced, succeeds).
2. Call `frost::presign` with the same 3 participants but `threshold = 1`. The check at line 72 evaluates `1 > 3` → false; no error is returned. Presign completes.
3. Call the FROST sign function (which internally calls `assert_sign_inputs`) with `threshold = 1`. The check at line 145 evaluates `1 > 3` → false; no error is returned.
4. With `threshold = 1`, the Lagrange coefficient for participant `P_i` evaluated at 0 over a set of size 1 is 1. Participant `P_i` computes `s_i = nonce_i + challenge * share_i` and the coordinator sums only `s_i` (one term), producing a valid aggregate signature `(R, s)`.
5. Verify the resulting signature against the group public key — it passes, despite only one participant contributing, violating the 2-of-3 threshold guarantee established at key generation.

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

**File:** src/frost/mod.rs (L79-87)
```rust
    let ctx = Comms::new();
    let fut = do_presign(
        ctx.shared_channel(),
        participants,
        me,
        args.keygen_out.private_share,
        rng,
    );
    Ok(make_protocol(ctx, fut))
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

**File:** src/thresholds.rs (L9-18)
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
```
