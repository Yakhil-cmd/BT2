### Title
Unvalidated `old_threshold` in `assert_reshare_keys_invariants` Silently Bypasses the Intersection Safety Guard — (File: `src/dkg.rs`)

---

### Summary

`assert_reshare_keys_invariants` accepts the `old_threshold` parameter without applying the same bounds checks that `assert_key_invariants` applies to the new threshold. When `old_threshold = 0` is supplied, the sole guard that enforces the protocol invariant `OldThreshold ≤ |intersection|` evaluates to `usize < 0`, which is always `false` in Rust's unsigned arithmetic, silently passing. The reshare then proceeds with an insufficient number of old participants contributing their shares, causing every honest participant to receive a `ProtocolError` at the key-consistency check deep inside `do_keyshare`, permanently denying the reshare.

---

### Finding Description

The protocol specification in `docs/dkg.md` mandates at Round 1:

> Each P_i asserts that `OldThreshold ≤ |I|` [1](#0-0) 

The implementation of this assertion lives in `assert_reshare_keys_invariants`:

```rust
if old_participants.intersection(&participants).len() < old_threshold {
    return Err(InitializationError::NotEnoughParticipantsForNewThreshold { ... });
}
``` [2](#0-1) 

`old_threshold` is a `usize` derived directly from the caller-supplied `impl Into<ReconstructionLowerBound>` argument with no prior validation: [3](#0-2) 

By contrast, the **new** threshold is immediately routed through `assert_key_invariants`, which enforces `threshold >= 2` and `threshold <= participants.len()`: [4](#0-3) 

No equivalent check is applied to `old_threshold`. When a caller passes `old_threshold = 0`:

- `intersection.len() < 0usize` is always `false` (Rust unsigned arithmetic).
- The guard returns no error regardless of how many old participants are actually present in the new set.
- `do_reshare` is invoked, computes the Lagrange-interpolated secret over the (potentially empty or undersized) intersection, and calls `do_keyshare`.
- Inside `do_keyshare`, the reconstructed public key will not match `old_public_key`, triggering:

```rust
if old_vk != verifying_key {
    return Err(ProtocolError::AssertionFailed(
        "new public key does not match old public key".to_string(),
    ));
}
``` [5](#0-4) 

Every honest participant receives this error after completing all network rounds, permanently blocking the reshare.

The same function is also called by `refresh`, which passes `old_threshold` as both the old and new threshold: [6](#0-5) 

So `refresh` is equally affected.

---

### Impact Explanation

**High — Permanent denial of reshare/refresh for honest parties.**

A caller (malicious coordinator or buggy integration) who supplies `old_threshold = 0` bypasses the only guard that enforces the minimum intersection requirement. The protocol then runs all network rounds before failing at the key-consistency check, leaving every honest participant in an aborted state with no valid output. Because the abort happens inside the async state machine after all communication has occurred, honest parties cannot distinguish this from a legitimate protocol failure and cannot recover without restarting from scratch with corrected parameters.

Supplying an enormous `old_threshold` (e.g., `usize::MAX`) causes the intersection check to always fire, permanently rejecting any reshare attempt — also a denial of reshare.

---

### Likelihood Explanation

The `reshare()` public API accepts `old_threshold` as a plain caller-supplied value with no library-side bounds enforcement. The new threshold is validated; the old threshold is not — an asymmetry that is easy to trigger accidentally (off-by-one, wrong variable) or intentionally by a malicious coordinator. The `ReconstructionLowerBound` wrapper type provides no inherent minimum enforcement. [7](#0-6) 

---

### Recommendation

Apply the same bounds checks to `old_threshold` that `assert_key_invariants` applies to the new threshold. Concretely, inside `assert_reshare_keys_invariants`, before the intersection check, add:

```rust
if old_threshold < 2 {
    return Err(InitializationError::ThresholdTooSmall { threshold: old_threshold, min: 2 });
}
if old_threshold > old_participants_list.len() {
    return Err(InitializationError::ThresholdTooLarge { threshold: old_threshold, max: old_participants_list.len() });
}
```

This mirrors the existing validation pattern and closes both the zero-bypass and the enormous-value DoS.

---

### Proof of Concept

```rust
// Attacker/buggy coordinator calls reshare with old_threshold = 0
reshare::<Secp256K1Sha256>(
    &old_participants,   // e.g. [P1, P2, P3], actual threshold was 2
    0usize,              // old_threshold = 0  ← invalid, not caught
    old_signing_key,
    old_public_key,
    &new_participants,
    2usize,              // new_threshold, correctly validated
    me,
    rng,
)
```

1. `assert_reshare_keys_invariants` converts `old_threshold` to `0usize`.
2. The check `intersection.len() < 0usize` is always `false` → no error returned. [8](#0-7) 
3. `do_reshare` is called. The intersection may have fewer than 2 old participants.
4. Lagrange interpolation over the undersized intersection produces an incorrect secret. [9](#0-8) 
5. `do_keyshare` computes a public key that does not match `old_public_key` and aborts with `"new public key does not match old public key"`. [5](#0-4) 
6. All honest participants receive `ProtocolError::AssertionFailed` — reshare permanently denied.

### Citations

**File:** docs/dkg.md (L52-54)
```markdown
$\quad$ `+++` Each $P_i$ sets $I \gets \set{P_1 \ldots P_N} \cap \mathit{OldSigners}$

$\quad$ `+++` Each $P_i$ asserts that $\mathsf{OldThreshold} \leq |I|$.
```

**File:** src/dkg.rs (L489-495)
```rust
    if let Some(old_vk) = old_verification_key {
        // check the equality between the old key and the new key without failing the unwrap
        if old_vk != verifying_key {
            return Err(ProtocolError::AssertionFailed(
                "new public key does not match old public key".to_string(),
            ));
        }
```

**File:** src/dkg.rs (L579-582)
```rust
    // Step 1.1
    if threshold < 2 {
        return Err(InitializationError::ThresholdTooSmall { threshold, min: 2 });
    }
```

**File:** src/dkg.rs (L611-620)
```rust
    let intersection = old_participants.intersection(&participants);
    // either extract the share and linearize it or set it to zero
    let secret = old_signing_key
        .map(|x_i| {
            intersection
                .lagrange::<C>(me)
                .map(|lambda| lambda * x_i.to_scalar())
        })
        .transpose()?
        .unwrap_or_else(<C::Group as Group>::Field::zero);
```

**File:** src/dkg.rs (L643-647)
```rust
    old_threshold: impl Into<ReconstructionLowerBound>,
    old_participants: &[Participant],
) -> Result<(ParticipantList, ParticipantList), InitializationError> {
    let threshold = usize::from(threshold.into());
    let old_threshold = usize::from(old_threshold.into());
```

**File:** src/dkg.rs (L654-660)
```rust
    // Step 1.1
    if old_participants.intersection(&participants).len() < old_threshold {
        return Err(InitializationError::NotEnoughParticipantsForNewThreshold {
            threshold: old_threshold,
            participants: old_participants.intersection(&participants).len(),
        });
    }
```

**File:** src/lib.rs (L165-172)
```rust
    let (participants, old_participants) = assert_reshare_keys_invariants::<C>(
        old_participants,
        me,
        threshold,
        old_signing_key,
        threshold,
        old_participants,
    )?;
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
