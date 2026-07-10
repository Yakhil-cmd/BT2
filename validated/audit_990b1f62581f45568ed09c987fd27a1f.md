### Title
DKG Threshold Upper-Bound Check Uses `>` Instead of `>=`, Allowing `threshold = N` in Violation of Specification — (File: `src/dkg.rs`)

### Summary

The DKG specification mandates the strict inequality `1 < threshold < N`. The implementation of `assert_key_invariants` enforces the lower bound correctly (`threshold >= 2`) but uses a non-strict upper-bound check (`threshold > N` → error), silently permitting `threshold = N`. A caller who configures `threshold = N` produces a key setup where all N participants are required to sign, enabling a single malicious participant — well within the BFT fault-tolerance budget — to permanently deny signing and resharing for all honest parties.

---

### Finding Description

The DKG specification in `docs/dkg.md` states at Round 1.1:

> "Each $P_i$ asserts that $1 < \mathsf{threshold} < N$."

Both inequalities are **strict**. The implementation in `assert_key_invariants` translates this as:

```rust
// Step 1.1 — upper bound
if threshold > participants.len() {          // ← should be >=
    return Err(InitializationError::ThresholdTooLarge { ... });
}
// Step 1.1 — lower bound
if threshold < 2 {                           // ← correctly strict
    return Err(InitializationError::ThresholdTooSmall { ... });
}
```

The lower bound correctly rejects `threshold = 1` (enforcing `threshold > 1`). The upper bound, however, only rejects `threshold > N`, silently accepting `threshold = N`. The spec requires `threshold < N` (strict), so `threshold = N` must also be rejected.

`assert_key_invariants` is the shared validation entry point called by every DKG operation:
- `keygen` → `assert_key_invariants`
- `assert_reshare_keys_invariants` → `assert_key_invariants`
- `do_keygen`, `do_reshare`, `do_refresh` all flow through these guards

The mismatch is therefore present across all DKG entry points.

---

### Impact Explanation

When `threshold = N`:

1. The Shamir polynomial has degree `N − 1`; reconstruction requires all N shares.
2. Every signing operation requires all N participants to be present and cooperative.
3. Every resharing operation also requires all N old participants to cooperate (since `old_threshold = N` is equally accepted).

A single malicious participant — which is within the BFT budget of `MaxFaulty = ⌊(N−1)/3⌋` for any `N ≥ 4` — can permanently deny signing by simply refusing to send their signature share. Because resharing is equally blocked (it also requires all N old participants), honest parties cannot recover by rotating the key set. The denial is permanent.

**Impact class: High — Permanent denial of signing and resharing for honest parties.**

---

### Likelihood Explanation

The `threshold` parameter is a direct, unchecked caller input. Any integrator who passes `threshold = participants.len()` (e.g., intending "unanimous consent") will silently produce a key setup that the spec explicitly forbids. A malicious participant who learns the threshold is `N` can then refuse to sign at any future signing session, with no recourse for honest parties. The entry path requires no special privilege: it is reachable by any library caller invoking `keygen` or `reshare`.

---

### Recommendation

Change the upper-bound check in `assert_key_invariants` from strict-greater-than to greater-than-or-equal, matching the spec's `threshold < N`:

```rust
// Before (incorrect — allows threshold == N):
if threshold > participants.len() {

// After (correct — enforces threshold < N per spec):
if threshold >= participants.len() {
```

Additionally, update the error message and the `ThresholdTooLarge` variant's `max` field to reflect `participants.len() - 1` as the maximum permitted value, and add a regression test asserting that `threshold = N` is rejected.

---

### Proof of Concept

**Spec reference** — strict upper bound: [1](#0-0) 

**Implementation — non-strict upper bound (the bug):** [2](#0-1) 

**Lower bound — correctly strict for comparison:** [3](#0-2) 

**`assert_reshare_keys_invariants` delegates to the same flawed guard:** [4](#0-3) 

Concrete scenario:

```
N = 4 participants, threshold = 4 (= N)
MaxFaulty = ⌊(4−1)/3⌋ = 1  →  one malicious participant is within tolerance

1. Caller invokes keygen(participants=[P1,P2,P3,P4], threshold=4)
   → assert_key_invariants: 4 > 4 is false → no error → keygen succeeds

2. Any future sign() call requires all 4 shares.

3. Malicious P4 refuses to send its signature share.
   → Signing permanently fails for P1, P2, P3.

4. Reshare also requires all 4 old participants → equally blocked.
   → No recovery path exists.
```

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

**File:** src/dkg.rs (L579-582)
```rust
    // Step 1.1
    if threshold < 2 {
        return Err(InitializationError::ThresholdTooSmall { threshold, min: 2 });
    }
```

**File:** src/dkg.rs (L649-649)
```rust
    let participants = assert_key_invariants(participants, me, threshold)?;
```
