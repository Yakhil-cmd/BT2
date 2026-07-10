### Title
Off-by-One in DKG Threshold Upper-Bound Validation Allows `threshold == N`, Enabling Permanent Denial of Signing — (`File: src/dkg.rs`)

---

### Summary

The DKG specification mandates the strict inequality `1 < threshold < N`. The implementation of `assert_key_invariants` uses a non-strict upper-bound check (`threshold > N` → error), which silently accepts `threshold == N`. A malicious coordinator or participant who sets `threshold = N` during key generation produces a valid DKG output that requires all N parties to sign. Any single party subsequently going offline permanently blocks signing for all honest parties.

---

### Finding Description

The protocol specification in `docs/dkg.md` Round 1, Step 1.1 states:

> "Each P_i asserts that **1 < threshold < N**."

Both inequalities are strict. The upper bound `threshold < N` is intentional: it ensures at least one party can be absent or malicious without permanently blocking signing.

The enforcement in `assert_key_invariants` is:

```rust
// Step 1.1
// validate threshold
if threshold > participants.len() {          // ← should be >=
    return Err(InitializationError::ThresholdTooLarge { ... });
}
if threshold < 2 {
    return Err(InitializationError::ThresholdTooSmall { ... });
}
``` [1](#0-0) 

The condition `threshold > participants.len()` rejects only `threshold > N`, allowing `threshold == N` to pass. The spec requires `threshold < N` (strict), so the correct guard is `threshold >= participants.len()`.

This function is the sole validation gate called by the public `keygen` and `reshare` entry points before any protocol execution begins: [2](#0-1) [3](#0-2) 

When `threshold == N` is accepted, `do_keyshare` generates a degree-`(N-1)` polynomial:

```rust
let degree = threshold.value().checked_sub(1)...;
let secret_coefficients = Polynomial::<C>::generate_polynomial(Some(secret), degree, rng)?;
``` [4](#0-3) 

A degree-`(N-1)` polynomial requires all N evaluations to reconstruct the secret — meaning every single participant must be present for any subsequent signing, presigning, or CKD operation.

---

### Impact Explanation

**High: Permanent denial of signing, key generation, reshare, refresh, or CKD for honest parties under valid protocol inputs.**

With `threshold == N` accepted by the library:

1. DKG completes successfully and produces a `KeygenOutput` that appears valid.
2. All downstream signing protocols (`ot_based_ecdsa::sign`, `frost::eddsa::sign_v1/v2`, `robust_ecdsa::sign`, CKD) require at least `threshold` participants. With `threshold == N`, every single party must participate.
3. If any one party goes offline — including the malicious party who proposed `threshold == N` — signing is permanently blocked. There is no recovery path without a full reshare, which itself requires `threshold` (== N) old participants.

---

### Likelihood Explanation

The threshold is a caller-supplied parameter. In a multi-party deployment, a malicious coordinator who controls the DKG setup can propose `threshold = N`. Honest participants invoke `keygen` with this value; the library accepts it without error. The malicious party participates honestly through DKG (to produce a valid shared key), then goes permanently offline. Honest parties are left with a key they can never use. The attack requires no cryptographic capability — only the ability to supply a threshold value that the library's own spec forbids but its code accepts.

---

### Recommendation

Change the upper-bound check in `assert_key_invariants` from strict-greater-than to greater-than-or-equal, to enforce the spec's strict inequality `threshold < N`:

```rust
// Step 1.1 — spec requires 1 < threshold < N (strict upper bound)
if threshold >= participants.len() {   // was: threshold > participants.len()
    return Err(InitializationError::ThresholdTooLarge {
        threshold,
        max: participants.len() - 1,   // update max to reflect N-1
    });
}
```

Apply the same correction to `validate_triple_inputs` in `src/ecdsa/ot_based_ecdsa/triples/generation.rs`, which contains an identical non-strict upper-bound check: [5](#0-4) 

---

### Proof of Concept

1. Call `keygen` with `participants = [P1, P2, P3]` and `threshold = 3` (== N).
2. `assert_key_invariants` checks `3 > 3` → false → no error. DKG proceeds.
3. All three parties complete DKG and hold shares of a degree-2 polynomial.
4. Attempt signing with only `[P1, P2]` (threshold = 3 required, only 2 present): signing fails.
5. P3 (the malicious party) goes permanently offline.
6. Signing is permanently blocked for P1 and P2 — they hold valid key shares but can never produce a signature.

The spec's Round 1.1 assertion `threshold < N` would have caught `threshold = 3` with `N = 3` and aborted the DKG before any key material was generated. The code's non-strict check silently accepts it. [1](#0-0) [6](#0-5)

### Citations

**File:** src/dkg.rs (L372-377)
```rust
    // the degree of the polynomial is threshold - 1
    let degree = threshold
        .value()
        .checked_sub(1)
        .ok_or(ProtocolError::IntegerOverflow)?;
    let secret_coefficients = Polynomial::<C>::generate_polynomial(Some(secret), degree, rng)?;
```

**File:** src/dkg.rs (L571-582)
```rust
    // Step 1.1
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

**File:** src/lib.rs (L98-101)
```rust
    let comms = Comms::new();
    let participants = assert_key_invariants(participants, me, threshold)?;
    let fut = do_keygen::<C>(comms.shared_channel(), participants, me, threshold, rng);
    Ok(make_protocol(comms, fut))
```

**File:** src/lib.rs (L122-129)
```rust
    let (participants, old_participants) = assert_reshare_keys_invariants::<C>(
        new_participants,
        me,
        threshold,
        old_signing_key,
        old_threshold,
        old_participants,
    )?;
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

**File:** docs/dkg.md (L50-50)
```markdown
1.1 Each $P_i$ asserts that $1 < \mathsf{threshold} < N$.
```
