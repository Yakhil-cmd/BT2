### Title
Non-Strict Threshold Upper-Bound Check Allows `threshold == N`, Enabling Permanent Denial of Signing and Resharing — (`src/dkg.rs`)

---

### Summary

`assert_key_invariants` in `src/dkg.rs` uses a non-strict comparison (`threshold > participants.len()`) to validate the upper bound of the threshold parameter. This allows `threshold == N` (where N is the total participant count), which the protocol specification explicitly prohibits. A library caller who sets `threshold == N` creates a key-share configuration where any single participant can permanently block all future signing and resharing sessions.

---

### Finding Description

The protocol specification in `docs/dkg.md` states at Step 1.1:

> Each $P_i$ asserts that $1 < \mathsf{threshold} < N$.

The upper bound is a **strict** inequality: `threshold < N`. However, the enforcement in `assert_key_invariants` is:

```rust
// src/dkg.rs:573-578
if threshold > participants.len() {
    return Err(InitializationError::ThresholdTooLarge {
        threshold,
        max: participants.len(),
    });
}
```

The condition `threshold > participants.len()` only rejects `threshold > N`; it silently accepts `threshold == N`. This is the exact same class of off-by-one as the external report's `>` vs `>=` check.

The same non-strict pattern appears in every other entry-point that calls `assert_key_invariants` or performs its own threshold check:

- `validate_triple_inputs` in `src/ecdsa/ot_based_ecdsa/triples/generation.rs:693` — triple generation
- `assert_sign_inputs` in `src/frost/mod.rs:145` — FROST signing
- `presign` in `src/ecdsa/ot_based_ecdsa/presign.rs:31` — OT-based ECDSA presigning

When `threshold == N` is used for DKG, the resulting key shares require **all N participants** to cooperate for every signing session. A single participant who refuses to send their share permanently blocks signing. Worse, the resharing guard in `assert_reshare_keys_invariants` is:

```rust
// src/dkg.rs:655-659
if old_participants.intersection(&participants).len() < old_threshold {
    return Err(InitializationError::NotEnoughParticipantsForNewThreshold { ... });
}
```

If `old_threshold == N`, the intersection must contain all N old participants. A single malicious participant who refuses to join the new participant set makes `|intersection| <= N-1 < old_threshold`, so resharing also permanently fails. There is no recovery path that does not require the malicious participant's cooperation.

---

### Impact Explanation

**High — Permanent denial of signing and resharing for honest parties.**

Once a key is generated with `threshold == N`:
- Every signing session requires all N participants; any single dropout causes the session to fail.
- Resharing to a lower threshold also requires all N old participants; the malicious participant can veto it.
- The honest parties' key material is permanently locked and unusable.

This matches the allowed impact: *"High: Permanent denial of signing, key generation, reshare, refresh, or CKD for honest parties under valid protocol inputs and documented trust assumptions."*

---

### Likelihood Explanation

The library exposes `threshold` as a caller-controlled parameter with no documentation warning against `threshold == N` at the API level. A caller who wants "all participants must sign" will naturally pass `threshold = participants.len()`, which the library accepts without error. The spec's strict inequality is only stated in `docs/dkg.md`, not enforced in code. Once the key is generated, a single malicious participant (one of the N key-holders) can exploit the situation by simply refusing to participate in any signing or resharing round.

---

### Recommendation

Change every non-strict upper-bound check to a strict one, matching the spec's `threshold < N`:

**`src/dkg.rs` (`assert_key_invariants`)**:
```rust
// Before (non-strict — allows threshold == N):
if threshold > participants.len() {

// After (strict — enforces threshold < N per spec):
if threshold >= participants.len() {
```

Apply the same fix to:
- `validate_triple_inputs` in `src/ecdsa/ot_based_ecdsa/triples/generation.rs`
- `assert_sign_inputs` in `src/frost/mod.rs`
- `presign` in `src/ecdsa/ot_based_ecdsa/presign.rs`

---

### Proof of Concept

1. Caller invokes `keygen` with `participants = [A, B, C]` and `threshold = 3`. The call succeeds — no error is returned.
2. All three participants complete DKG and hold valid key shares.
3. Participant C (malicious) decides to refuse all future signing requests.
4. Honest participants A and B attempt to sign: they call `sign` with `threshold = 3` and `participants = [A, B, C]`. C never sends its share. The signing session hangs or times out permanently.
5. A and B attempt resharing to a new set `[A, B, D]` with `new_threshold = 2`. `assert_reshare_keys_invariants` computes `intersection([A,B,C], [A,B,D]) = [A,B]`, which has size 2 < `old_threshold = 3`, so resharing is rejected with `NotEnoughParticipantsForNewThreshold`. Recovery is impossible without C's cooperation.

**Root cause line**: [1](#0-0) 

**Spec requirement violated**: [2](#0-1) 

**Same pattern in triple generation**: [3](#0-2) 

**Same pattern in FROST signing**: [4](#0-3) 

**Resharing recovery also blocked**: [5](#0-4)

### Citations

**File:** src/dkg.rs (L573-578)
```rust
    if threshold > participants.len() {
        return Err(InitializationError::ThresholdTooLarge {
            threshold,
            max: participants.len(),
        });
    }
```

**File:** src/dkg.rs (L655-659)
```rust
    if old_participants.intersection(&participants).len() < old_threshold {
        return Err(InitializationError::NotEnoughParticipantsForNewThreshold {
            threshold: old_threshold,
            participants: old_participants.intersection(&participants).len(),
        });
```

**File:** docs/dkg.md (L50-54)
```markdown
1.1 Each $P_i$ asserts that $1 < \mathsf{threshold} < N$.

$\quad$ `+++` Each $P_i$ sets $I \gets \set{P_1 \ldots P_N} \cap \mathit{OldSigners}$

$\quad$ `+++` Each $P_i$ asserts that $\mathsf{OldThreshold} \leq |I|$.
```

**File:** src/ecdsa/ot_based_ecdsa/triples/generation.rs (L693-698)
```rust
    if threshold_value > participants.len() {
        return Err(InitializationError::ThresholdTooLarge {
            threshold: threshold_value,
            max: participants.len(),
        });
    }
```

**File:** src/frost/mod.rs (L145-150)
```rust
    if threshold.value() > participants.len() {
        return Err(InitializationError::ThresholdTooLarge {
            threshold: threshold.value(),
            max: participants.len(),
        });
    }
```
