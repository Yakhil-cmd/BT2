### Title
Missing `me`-in-participants Validation in Triple Generation Entry Points — (`src/ecdsa/ot_based_ecdsa/triples/generation.rs`)

---

### Summary

`generate_triple` and `generate_triple_many` — the two public entry points for OT-based ECDSA Beaver triple generation — omit the check that `me` is a member of the supplied `participants` list. Every other protocol entry point in the library performs this check. When `me` is absent from the participant list, the multi-round protocol executes to completion but produces a triple share that is cryptographically inconsistent with the agreed-upon public triple, rendering the output unusable for presigning and permanently denying signing capability to the affected party.

---

### Finding Description

`validate_triple_inputs` is the shared validation helper called by both `generate_triple` and `generate_triple_many`: [1](#0-0) 

It validates participant count, threshold bounds, and uniqueness, but **never checks that `me` is contained in the resulting `ParticipantList`**. Both public entry points delegate all validation to this helper and then pass the unvalidated `me` directly into the async protocol: [2](#0-1) [3](#0-2) 

Every other protocol entry point in the library performs the missing check. For example, `presign` (OT-based), `sign` (OT-based), `presign` (robust), `sign` (robust), `ckd`, `assert_key_invariants` (DKG), and `assert_sign_inputs` (FROST) all contain: [4](#0-3) [5](#0-4) [6](#0-5) [7](#0-6) [8](#0-7) [9](#0-8) [10](#0-9) 

Triple generation is the sole entry point that omits this guard.

Inside `do_generation_many`, when `me` is absent from `participants`, the following concrete misbehaviors occur:

1. **`ParticipantMap::put(me, …)` silently no-ops.** `me`'s own commitment is never recorded in `all_commitments_vec`, because `put` checks `self.participants.indices.get(&participant)` and returns without inserting when the participant is unknown: [11](#0-10) 

2. **`participants.others(me)` returns every participant.** Because `me` is not in the list, the `others` iterator does not filter `me` out, so `me` sends private polynomial shares to all listed participants — parties who do not expect those messages and whose `recv_from_others` calls will ignore them: [12](#0-11) 

3. **`me` evaluates its own share at an out-of-set scalar.** `eval_at_participant(me)` computes a valid field evaluation at `me`'s scalar, but since `me` is not in the agreed participant set, the resulting `(a_i, b_i, c_i)` triple share is not a valid Shamir share of the public triple `(A, B, C)`: [13](#0-12) 

4. **The emitted `TriplePub` does not include `me`.** The `participants` field of the returned `TriplePub` is the original list, which excludes `me`: [14](#0-13) 

The triple share held by `me` is therefore inconsistent with the public triple. When `me` subsequently calls `presign` with this triple, `presign` will reject it because `me` is not in the participant list — permanently denying signing for `me` after the entire expensive multi-round triple generation has already completed.

---

### Impact Explanation

The output of `generate_triple` / `generate_triple_many` is a `(TripleShare, TriplePub)` pair. When `me ∉ participants`, the `TripleShare` is an evaluation of the sum polynomial at an out-of-set scalar and is cryptographically inconsistent with `TriplePub`. This constitutes **corruption of the triple generation output producing an unusable cryptographic output**, which is the direct prerequisite for OT-based ECDSA presigning. The affected party cannot proceed to presigning and therefore cannot sign — a permanent denial of signing capability.

This maps to: **High — Corruption of presign outputs so honest parties accept unusable cryptographic outputs.**

---

### Likelihood Explanation

The entry point is a public library API. Any caller — including a misconfigured honest node or a malicious participant deliberately supplying a `me` value outside the participant list — can trigger this path. No special privilege is required. The missing check is a straightforward omission that is inconsistent with every other protocol entry point in the same codebase, making accidental misconfiguration a realistic scenario.

---

### Recommendation

Add the same `me`-in-participants guard to `validate_triple_inputs` (or directly in `generate_triple` / `generate_triple_many`) that every other protocol entry point already enforces:

```rust
fn validate_triple_inputs(
    participants: &[Participant],
    me: Participant,                          // add me parameter
    threshold: impl Into<ReconstructionLowerBound>,
) -> Result<(ParticipantList, ReconstructionLowerBound), InitializationError> {
    // ... existing checks ...
    let participants =
        ParticipantList::new(participants).ok_or(InitializationError::DuplicateParticipants)?;

    // ADD: mirror the check present in every other entry point
    if !participants.contains(me) {
        return Err(InitializationError::MissingParticipant {
            role: "self",
            participant: me,
        });
    }

    Ok((participants, threshold))
}
```

---

### Proof of Concept

```
1. Construct participants = [P1, P2, P3], threshold = 2.
2. Call generate_triple(participants, me=P99, threshold=2, rng).
   → validate_triple_inputs succeeds (P99 not checked).
   → do_generation_many starts with me=P99 ∉ participants.
3. m.put(P99, commitment) → silently no-ops; P99's commitment never enters the map.
4. participants.others(P99) → returns [P1, P2, P3] (all participants).
5. Protocol completes; me=P99 holds TripleShare{a, b, c} evaluated at scalar(P99).
6. TriplePub.participants = [P1, P2, P3] (P99 absent).
7. Call presign(participants=[P1,P2,P3], me=P99, args=(triple, …)).
   → presign checks participants.contains(P99) → MissingParticipant error.
8. P99 cannot sign. Triple generation resources wasted. Signing permanently denied.
``` [1](#0-0) [2](#0-1)

### Citations

**File:** src/ecdsa/ot_based_ecdsa/triples/generation.rs (L284-296)
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
```

**File:** src/ecdsa/ot_based_ecdsa/triples/generation.rs (L297-306)
```rust
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

**File:** src/ecdsa/ot_based_ecdsa/triples/generation.rs (L717-727)
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
```

**File:** src/ecdsa/ot_based_ecdsa/triples/generation.rs (L730-740)
```rust
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

**File:** src/ecdsa/ot_based_ecdsa/presign.rs (L52-57)
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

**File:** src/ecdsa/robust_ecdsa/presign.rs (L45-50)
```rust
    if !participants.contains(me) {
        return Err(InitializationError::MissingParticipant {
            role: "self",
            participant: me,
        });
    }
```

**File:** src/ecdsa/robust_ecdsa/sign.rs (L51-57)
```rust
    // ensure my presence in the participant list
    if !participants.contains(me) {
        return Err(InitializationError::MissingParticipant {
            role: "self",
            participant: me,
        });
    }
```

**File:** src/confidential_key_derivation/protocol.rs (L88-93)
```rust
    if !participants.contains(me) {
        return Err(InitializationError::MissingParticipant {
            role: "self",
            participant: me,
        });
    }
```

**File:** src/dkg.rs (L589-594)
```rust
    if !participants.contains(me) {
        return Err(InitializationError::MissingParticipant {
            role: "self",
            participant: me,
        });
    }
```

**File:** src/frost/mod.rs (L137-142)
```rust
    if !participants.contains(me) {
        return Err(InitializationError::MissingParticipant {
            role: "self",
            participant: me,
        });
    }
```

**File:** src/participants.rs (L237-246)
```rust
    pub fn put(&mut self, participant: Participant, data: T) {
        if let Some(&i) = self.participants.indices.get(&participant) {
            if let Some(data_i) = self.data.get_mut(i) {
                if data_i.is_none() {
                    *data_i = Some(data);
                    self.count += 1;
                }
            }
        }
    }
```
