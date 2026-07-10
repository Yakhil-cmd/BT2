### Title
Inverted Condition in `assert_reshare_keys_invariants` Allows New Participant with Signing Key to Bypass Validation and Stall Reshare Protocol — (`src/dkg.rs`)

---

### Summary

`assert_reshare_keys_invariants` in `src/dkg.rs` contains an inverted guard condition. Its own comment states the intended check — "if me is not in the old participant set then ensure that `old_signing_key` is None" — but the code implements the **opposite** predicate. As a result, a new participant (not in the old set) who supplies a non-`None` `old_signing_key` passes the public-API validation gate, enters `do_reshare`, and then fails mid-execution when the Lagrange coefficient computation returns `ProtocolError::InvalidInterpolationArguments`. Because the participant aborts before sending any protocol messages, every other participant in the reshare session is left waiting indefinitely for messages that will never arrive, permanently denying the reshare for all honest parties.

---

### Finding Description

**Root cause — wrong predicate in the validation gate**

`assert_reshare_keys_invariants` is the sole pre-flight check called by the public `reshare` entry point before the async protocol future is spawned. [1](#0-0) 

The comment on line 662 documents the intended invariant:

> `// if me is not in the old participant set then ensure that old_signing_key is None`

The code on line 663 checks the **opposite** condition:

```rust
if old_participants.contains(me) && old_signing_key.is_none() {
```

This catches only the case where an *old* participant forgot to supply their key. It completely misses the symmetric case: a *new* participant (not in `old_participants`) who erroneously or maliciously supplies a non-`None` `old_signing_key`. That case passes the guard without error.

**Downstream failure in `do_reshare`**

After the guard passes, `reshare` calls `do_reshare` with the unchecked `old_signing_key`: [2](#0-1) 

Inside `do_reshare`, the first thing computed is the linearized secret: [3](#0-2) 

`intersection` is `old_participants ∩ new_participants`. Because `me` is not in `old_participants`, `me` is not in `intersection`. The call `intersection.lagrange::<C>(me)` delegates to `compute_lagrange_coefficient`, which explicitly returns an error when the queried point is absent from the point set: [4](#0-3) 

The `.transpose()?` on line 619 propagates this `ProtocolError::InvalidInterpolationArguments`, causing `do_reshare` to return immediately — **before sending a single protocol message**.

**Why `assert_keyshare_inputs` does not save the situation**

`assert_keyshare_inputs` (lines 23–55 of `src/dkg.rs`) does contain the correct symmetric check, but it is called inside `do_keyshare`, which is only reached *after* the Lagrange computation. Because the failure occurs before `do_keyshare` is ever invoked, that inner guard is never executed. [5](#0-4) 

---

### Impact Explanation

When the failing participant aborts before sending any messages, every other participant in the reshare session blocks indefinitely inside `recv_from_others`, waiting for messages from a participant that has already exited. This permanently denies the reshare for all honest parties in the session.

**Impact category:** High — Permanent denial of reshare for honest parties under valid protocol inputs and documented trust assumptions.

---

### Likelihood Explanation

The `reshare` function is a public library API. Any caller acting as a new participant (not in `old_participants`) can supply a non-`None` `old_signing_key`. This includes:

- An honest integrator who holds a key from a prior epoch and passes it by mistake (the validation function is supposed to catch exactly this class of misconfiguration).
- A malicious new participant who deliberately supplies a garbage key to abort the reshare session for all other parties.

The missing check is a single boolean predicate that the comment already describes correctly; the code simply has the condition inverted. The trigger is a single API call with a plausible argument combination.

---

### Recommendation

Replace the inverted condition with the two symmetric guards that together enforce both directions of the invariant:

```rust
// Step 1.1
// Old participant must supply their share
if old_participants.contains(me) && old_signing_key.is_none() {
    return Err(InitializationError::BadParameters(format!(
        "party {me:?} is present in the old participant list but provided no share"
    )));
}
// New participant must NOT supply a share (they have none)
if !old_participants.contains(me) && old_signing_key.is_some() {
    return Err(InitializationError::BadParameters(format!(
        "party {me:?} is not in the old participant list but provided a share"
    )));
}
```

This ensures the validation gate catches both failure modes before the async protocol future is spawned, matching the intent already documented in the comment.

---

### Proof of Concept

```
Setup:
  old_participants = [P1, P2, P3]  (threshold = 2)
  new_participants = [P1, P2, P3, P4]  (threshold = 2)
  me = P4  (new joiner, NOT in old_participants)
  old_signing_key = Some(<any SigningShare>)  // e.g. a key from a different epoch

Step 1: Call reshare::<C>(old_participants, 2, old_signing_key, old_pk, new_participants, 2, P4, rng)

Step 2: assert_reshare_keys_invariants is called.
  - old_participants.contains(P4) == false
  - old_signing_key.is_none() == false
  - Condition `old_participants.contains(me) && old_signing_key.is_none()` evaluates to
    `false && false` == false  →  NO ERROR RETURNED.

Step 3: do_reshare is called with old_signing_key = Some(...).
  - intersection = old_participants ∩ new_participants = {P1, P2, P3}
  - P4 is not in intersection.
  - intersection.lagrange::<C>(P4) returns Err(ProtocolError::InvalidInterpolationArguments).
  - .transpose()? propagates the error; do_reshare returns immediately.
  - P4 sends no messages.

Step 4: P1, P2, P3 are blocked in recv_from_others waiting for P4's round-1 message.
  Result: reshare session permanently stalled for all honest parties.
```

### Citations

**File:** src/dkg.rs (L39-44)
```rust
        } else {
            //  return error if me is part of the old participants set
            if !old_participants.contains(me) {
                return Err(ProtocolError::AssertionFailed(
                    format!("{me:?} is running Resharing with a non-zero share but does not belong to the old participant set")));
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

**File:** src/dkg.rs (L661-667)
```rust
    // Step 1.1
    // if me is not in the old participant set then ensure that old_signing_key is None
    if old_participants.contains(me) && old_signing_key.is_none() {
        return Err(InitializationError::BadParameters(format!(
            "party {me:?} is present in the old participant list but provided no share"
        )));
    }
```

**File:** src/lib.rs (L130-140)
```rust
    let fut = do_reshare(
        comms.shared_channel(),
        participants,
        me,
        threshold,
        old_signing_key,
        old_public_key,
        old_participants,
        rng,
    );
    Ok(make_protocol(comms, fut))
```

**File:** src/crypto/polynomials.rs (L437-440)
```rust
    // if i is not in the set of points
    if !contains_i {
        return Err(ProtocolError::InvalidInterpolationArguments);
    }
```
