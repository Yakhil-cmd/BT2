### Title
Missing `me` Membership Guard in Triple Generation Initialization — (`File: src/ecdsa/ot_based_ecdsa/triples/generation.rs`)

### Summary
`validate_triple_inputs`, the shared initialization function for both `generate_triple` and `generate_triple_many`, omits the `participants.contains(me)` check that every other protocol constructor in the library enforces. When `me` is absent from the participant list, the protocol proceeds into `do_generation_many` with an inconsistent identity, causing either a panic (denial of triple generation) or a structurally invalid triple share whose `TriplePub.participants` set does not include the party that produced it — corrupting downstream presigning.

---

### Finding Description

Every public protocol constructor in the library validates that `me` is a member of the participant list before creating the protocol state machine:

- `keygen()` → `assert_key_invariants` checks `!participants.contains(me)` [1](#0-0) 
- `reshare()` / `refresh()` → same path via `assert_key_invariants` [2](#0-1) 
- `presign()` (OT-based) checks `!participants.contains(me)` [3](#0-2) 
- `presign()` (robust) checks `!participants.contains(me)` [4](#0-3) 
- `sign()` (OT-based and robust) checks `!participants.contains(me)` [5](#0-4) 
- `ckd()` checks `!participants.contains(me)` [6](#0-5) 

`validate_triple_inputs`, however, only validates participant count, threshold bounds, and uniqueness — it never checks whether `me` is present:

```rust
fn validate_triple_inputs(
    participants: &[Participant],
    threshold: impl Into<ReconstructionLowerBound>,
) -> Result<(ParticipantList, ReconstructionLowerBound), InitializationError> {
    // ... count, threshold, duplicate checks only
    let participants =
        ParticipantList::new(participants).ok_or(InitializationError::DuplicateParticipants)?;
    Ok((participants, threshold))
    // ← no participants.contains(me) check
}
``` [7](#0-6) 

Both public entry points delegate to this function without adding the check themselves:

```rust
pub fn generate_triple(...) -> Result<impl Protocol<Output = TripleGenerationOutput>, InitializationError> {
    let (participants, threshold) = validate_triple_inputs(participants, threshold)?;
    // me is never validated against participants
    ...
}
pub fn generate_triple_many<const N: usize>(...) -> ... {
    let (participants, threshold) = validate_triple_inputs(participants, threshold)?;
    ...
}
``` [8](#0-7) 

Inside `do_generation_many`, the protocol immediately uses `me` as a key into a `ParticipantMap` built from the validated list:

```rust
let mut m = ParticipantMap::new(&participants);
m.put(me, *comi);   // me is not in participants → panic or silent corruption
``` [9](#0-8) 

Later, `participants.others(me)` returns the full participant list (since `me` is not filtered out), causing `me` to send private polynomial evaluations to every participant — including parties that never expect a message from `me`:

```rust
for p in participants.others(me) {
    let a_i_j = e.eval_at_participant(p)?.0;
    chan.send_private(wait3, p, &(a_i_j_v, b_i_j_v))?;
}
let a_i = e.eval_at_participant(me)?;   // evaluated at an out-of-set scalar
``` [10](#0-9) 

The final triple share is then stored with `TriplePub.participants` set to the original list (which excludes `me`), while `me` holds a share evaluated at an arbitrary scalar not agreed upon by any other party:

```rust
ret.push((
    TripleShare { a: *a_i, b: *b_i, c: *c_i },
    TriplePub { ..., participants: participants.clone().into(), threshold },
));
``` [11](#0-10) 

---

### Impact Explanation

**High — Corruption of presign outputs / permanent denial of triple generation.**

Two concrete outcomes:

1. **Panic / hard abort**: `ParticipantMap::put(me, …)` with `me` absent from the backing list will attempt `participants.index(me)`, which returns `Err(ProtocolError::InvalidIndex)`. If `put` propagates or panics on this, the entire triple generation session aborts for the calling party, permanently denying it the ability to produce triples and therefore to presign or sign.

2. **Structurally invalid triple**: If the panic path is not taken, `me` completes the protocol holding a `TripleShare` whose scalar was evaluated at an out-of-set point. The `TriplePub.participants` field records the original list (without `me`). When this triple is later passed to `presign()`, the threshold check `args.threshold != args.triple0.1.threshold` passes, but the participant-set mismatch is never detected, producing a presignature that cannot be combined with honest parties' shares — corrupting the presign output.

---

### Likelihood Explanation

**Medium.** The entry point is the public library API. Any application layer that constructs the participant list incorrectly (e.g., passes the full network participant set while `me` is a coordinator-only node not in that set, or makes an off-by-one error in list construction) will silently bypass the missing guard. Because every other constructor in the library catches this mistake and returns a clean `InitializationError`, callers have no reason to expect that `generate_triple` / `generate_triple_many` behave differently. The inconsistency makes the bug easy to trigger inadvertently and hard to diagnose.

---

### Recommendation

Add the same `me`-membership guard to `validate_triple_inputs` that every other constructor enforces, and thread `me` into the function:

```rust
fn validate_triple_inputs(
    participants: &[Participant],
    me: Participant,
    threshold: impl Into<ReconstructionLowerBound>,
) -> Result<(ParticipantList, ReconstructionLowerBound), InitializationError> {
    // ... existing count / threshold / duplicate checks ...
    let participants =
        ParticipantList::new(participants).ok_or(InitializationError::DuplicateParticipants)?;

    // ← add this guard, matching every other constructor
    if !participants.contains(me) {
        return Err(InitializationError::MissingParticipant {
            role: "self",
            participant: me,
        });
    }

    Ok((participants, threshold))
}
```

Update both call sites to pass `me`:

```rust
pub fn generate_triple(participants, me, threshold, rng) -> ... {
    let (participants, threshold) = validate_triple_inputs(participants, me, threshold)?;
    ...
}
pub fn generate_triple_many<const N: usize>(participants, me, threshold, rng) -> ... {
    let (participants, threshold) = validate_triple_inputs(participants, me, threshold)?;
    ...
}
``` [8](#0-7) 

---

### Proof of Concept

```rust
use threshold_signatures::ecdsa::ot_based_ecdsa::triples::generate_triple;
use threshold_signatures::participants::Participant;

let p1 = Participant::from(1u32);
let p2 = Participant::from(2u32);
let outsider = Participant::from(99u32);  // not in the list

// All other constructors would return InitializationError::MissingParticipant here.
// generate_triple silently accepts it and enters do_generation_many with me ∉ participants.
let result = generate_triple(
    &[p1, p2],   // participant list does NOT include outsider
    outsider,    // me = outsider
    2u32,
    rand::rngs::OsRng,
);
// Returns Ok(...) instead of Err(InitializationError::MissingParticipant { ... })
// Protocol then panics or produces a structurally invalid TripleShare.
assert!(result.is_ok()); // passes — missing guard confirmed
```

The root cause is exclusively in `validate_triple_inputs` at lines 681–708 of `src/ecdsa/ot_based_ecdsa/triples/generation.rs`, which is the only initialization helper in the library that omits the `participants.contains(me)` guard. [7](#0-6)

### Citations

**File:** src/dkg.rs (L588-594)
```rust
    // ensure my presence in the participant list
    if !participants.contains(me) {
        return Err(InitializationError::MissingParticipant {
            role: "self",
            participant: me,
        });
    }
```

**File:** src/lib.rs (L120-129)
```rust
    let comms = Comms::new();
    let threshold = new_threshold;
    let (participants, old_participants) = assert_reshare_keys_invariants::<C>(
        new_participants,
        me,
        threshold,
        old_signing_key,
        old_threshold,
        old_participants,
    )?;
```

**File:** src/ecdsa/ot_based_ecdsa/presign.rs (L52-57)
```rust
    if !participants.contains(me) {
        return Err(InitializationError::MissingParticipant {
            role: "self",
            participant: me,
        });
    }
```

**File:** src/ecdsa/robust_ecdsa/presign.rs (L45-50)
```rust
    if !participants.contains(me) {
        return Err(InitializationError::MissingParticipant {
            role: "self",
            participant: me,
        });
    }
```

**File:** src/ecdsa/ot_based_ecdsa/sign.rs (L41-47)
```rust
    // ensure my presence in the participant list
    if !participants.contains(me) {
        return Err(InitializationError::MissingParticipant {
            role: "self",
            participant: me,
        });
    }
```

**File:** src/confidential_key_derivation/protocol.rs (L87-93)
```rust
    // ensure my presence in the participant list
    if !participants.contains(me) {
        return Err(InitializationError::MissingParticipant {
            role: "self",
            participant: me,
        });
    }
```

**File:** src/ecdsa/ot_based_ecdsa/triples/generation.rs (L171-173)
```rust
        let mut m = ParticipantMap::new(&participants);
        m.put(me, *comi);
        all_commitments_vec.push(m);
```

**File:** src/ecdsa/ot_based_ecdsa/triples/generation.rs (L284-306)
```rust
        for p in participants.others(me) {
            let mut a_i_j_v = vec![];
            let mut b_i_j_v = vec![];
            for i in 0..N {
                let e = &e_v[i];
                let f = &f_v[i];
                let a_i_j = e.eval_at_participant(p)?.0;
                let b_i_j = f.eval_at_participant(p)?.0;
                a_i_j_v.push(a_i_j);
                b_i_j_v.push(b_i_j);
            }
            chan.send_private(wait3, p, &(a_i_j_v, b_i_j_v))?;
        }
        let mut a_i_v = vec![];
        let mut b_i_v = vec![];
        for i in 0..N {
            let e = &e_v[i];
            let f = &f_v[i];
            let a_i = e.eval_at_participant(me)?;
            let b_i = f.eval_at_participant(me)?;
            a_i_v.push(a_i.0);
            b_i_v.push(b_i.0);
        }
```

**File:** src/ecdsa/ot_based_ecdsa/triples/generation.rs (L655-668)
```rust
        ret.push((
            TripleShare {
                a: *a_i,
                b: *b_i,
                c: *c_i,
            },
            TriplePub {
                big_a,
                big_b,
                big_c,
                participants: participants.clone().into(),
                threshold,
            },
        ));
```

**File:** src/ecdsa/ot_based_ecdsa/triples/generation.rs (L681-708)
```rust
fn validate_triple_inputs(
    participants: &[Participant],
    threshold: impl Into<ReconstructionLowerBound>,
) -> Result<(ParticipantList, ReconstructionLowerBound), InitializationError> {
    let threshold = threshold.into();
    let threshold_value = threshold.value();
    if participants.len() < 2 {
        return Err(InitializationError::NotEnoughParticipants {
            participants: participants.len(),
        });
    }
    // Spec 1.1
    if threshold_value > participants.len() {
        return Err(InitializationError::ThresholdTooLarge {
            threshold: threshold_value,
            max: participants.len(),
        });
    }
    if threshold_value < 2 {
        return Err(InitializationError::ThresholdTooSmall {
            threshold: threshold_value,
            min: 2,
        });
    }
    let participants =
        ParticipantList::new(participants).ok_or(InitializationError::DuplicateParticipants)?;
    Ok((participants, threshold))
}
```

**File:** src/ecdsa/ot_based_ecdsa/triples/generation.rs (L717-740)
```rust
pub fn generate_triple(
    participants: &[Participant],
    me: Participant,
    threshold: impl Into<ReconstructionLowerBound>,
    rng: impl CryptoRngCore + Send + 'static,
) -> Result<impl Protocol<Output = TripleGenerationOutput>, InitializationError> {
    let (participants, threshold) = validate_triple_inputs(participants, threshold)?;
    let ctx = Comms::new();
    let fut = do_generation(ctx.clone(), participants, me, threshold, rng);
    Ok(make_protocol(ctx, fut))
}

/// As [`generate_triple`] but for many triples at once
pub fn generate_triple_many<const N: usize>(
    participants: &[Participant],
    me: Participant,
    threshold: impl Into<ReconstructionLowerBound>,
    rng: impl CryptoRngCore + Send + 'static,
) -> Result<impl Protocol<Output = TripleGenerationOutputMany>, InitializationError> {
    let (participants, threshold) = validate_triple_inputs(participants, threshold)?;
    let ctx = Comms::new();
    let fut = do_generation_many::<N>(ctx.clone(), participants, me, threshold, rng);
    Ok(make_protocol(ctx, fut))
}
```
