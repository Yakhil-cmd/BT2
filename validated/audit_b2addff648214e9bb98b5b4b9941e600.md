### Title
Off-by-One in Threshold Upper-Bound Validation Allows N-of-N Configuration, Enabling Permanent Denial of Signing - (File: src/dkg.rs)

### Summary
The protocol specification mandates a **strict** upper bound `1 < threshold < N` for the reconstruction threshold, but every threshold validation function in the codebase enforces a **non-strict** upper bound (`threshold <= N`). This off-by-one discrepancy allows a malicious coordinator to configure `threshold = N`, creating an N-of-N scheme where any single participant can permanently block all signing operations by refusing to cooperate.

### Finding Description

The PedPop+ specification in `docs/dkg.md` at Step 1.1 states:

> Each P_i asserts that `1 < threshold < N`

The upper bound is **strict**: `threshold` must be strictly less than `N` (the total participant count).

However, the implementation in `assert_key_invariants` uses a non-strict comparison:

```rust
// src/dkg.rs line 573
if threshold > participants.len() {
    return Err(InitializationError::ThresholdTooLarge { ... });
}
```

This check only rejects `threshold > N`, silently accepting `threshold == N`. The same non-strict pattern is repeated in every other threshold validation site:

- `src/frost/mod.rs` line 72 (`presign`): `args.threshold.value() > participants.len()`
- `src/frost/mod.rs` line 145 (`assert_sign_inputs`): `threshold.value() > participants.len()`
- `src/ecdsa/ot_based_ecdsa/triples/generation.rs` line 693 (`validate_triple_inputs`): `threshold_value > participants.len()`
- `src/ecdsa/ot_based_ecdsa/presign.rs` line 31: `args.threshold.value() > participants.len()`

All four sites are inconsistent with the spec's strict `<` requirement.

### Impact Explanation

When `threshold = N` is accepted:
1. The DKG polynomial has degree `N - 1`, requiring all N shares for reconstruction.
2. Every subsequent signing call requires all N participants to contribute.
3. A single participant who refuses to send their signature share permanently blocks all signing for the honest majority.

This maps directly to the allowed **High** impact: *Permanent denial of signing for honest parties under valid protocol inputs and documented trust assumptions.*

### Likelihood Explanation

A malicious coordinator who controls the session setup can pass `threshold = N` to all participants. Since the code accepts this value without error, all participants proceed through DKG successfully. The resulting key is permanently locked behind full-N participation, giving any single colluding or later-turned-malicious participant a permanent veto over signing.

### Recommendation

Change every upper-bound check from `>` to `>=` to enforce the spec's strict inequality `threshold < N`:

```rust
// src/dkg.rs — assert_key_invariants
if threshold >= participants.len() {   // was: threshold > participants.len()
    return Err(InitializationError::ThresholdTooLarge { ... });
}
```

Apply the same fix to `src/frost/mod.rs` (both `presign` and `assert_sign_inputs`), `src/ecdsa/ot_based_ecdsa/triples/generation.rs` (`validate_triple_inputs`), and `src/ecdsa/ot_based_ecdsa/presign.rs`.

### Proof of Concept

**Spec (docs/dkg.md, line 50):** [1](#0-0) 

The spec mandates `threshold < N` (strict).

**Code (src/dkg.rs, line 573):** [2](#0-1) 

The code uses `>` instead of `>=`, accepting `threshold == N`.

**Same pattern in FROST presign (src/frost/mod.rs, line 72):** [3](#0-2) 

**Same pattern in FROST assert_sign_inputs (src/frost/mod.rs, line 145):** [4](#0-3) 

**Same pattern in triple generation (src/ecdsa/ot_based_ecdsa/triples/generation.rs, line 693):** [5](#0-4) 

**Attack path:**
1. Malicious coordinator initializes DKG with `threshold = N` across all N participants.
2. All participants call `assert_key_invariants` — the check `threshold > N` is false, so no error is raised.
3. DKG completes successfully, producing shares that require all N parties for reconstruction.
4. Any single participant (including the coordinator or a later-corrupted node) refuses to participate in signing.
5. Signing is permanently blocked for all honest parties — no subset of `N - 1` participants can produce a valid signature.

### Citations

**File:** docs/dkg.md (L50-50)
```markdown
1.1 Each $P_i$ asserts that $1 < \mathsf{threshold} < N$.
```

**File:** src/dkg.rs (L571-578)
```rust
    // Step 1.1
    // validate threshold
    if threshold > participants.len() {
        return Err(InitializationError::ThresholdTooLarge {
            threshold,
            max: participants.len(),
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

**File:** src/ecdsa/ot_based_ecdsa/triples/generation.rs (L692-698)
```rust
    // Spec 1.1
    if threshold_value > participants.len() {
        return Err(InitializationError::ThresholdTooLarge {
            threshold: threshold_value,
            max: participants.len(),
        });
    }
```
