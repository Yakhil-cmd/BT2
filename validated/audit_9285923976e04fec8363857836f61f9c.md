### Title
Missing Validation in `assert_reshare_keys_invariants` Allows New Participant with Signing Key to Permanently Stall Reshare for Honest Parties — (File: `src/dkg.rs`)

---

### Summary

`assert_reshare_keys_invariants` in `src/dkg.rs` contains a comment stating it should reject a new participant (not in `old_participants`) who supplies a non-`None` signing key, but the actual guard only checks the opposite case. A malicious new participant can therefore pass initialization, enter `do_reshare`, and cause `do_keyshare` to abort before emitting any protocol messages. Every honest participant then waits indefinitely for the missing messages, permanently stalling the reshare.

---

### Finding Description

`assert_reshare_keys_invariants` is the public pre-flight check for the reshare protocol. Its inline comment reads:

> `// if me is not in the old participant set then ensure that old_signing_key is None`

The implemented guard, however, is:

```rust
// src/dkg.rs  lines 662-667
if old_participants.contains(me) && old_signing_key.is_none() {
    return Err(InitializationError::BadParameters(format!(
        "party {me:?} is present in the old participant list but provided no share"
    )));
}
``` [1](#0-0) 

This rejects **old participant + no key**, but silently accepts **new participant + key present** — the exact case the comment says must be rejected.

When a new participant (absent from `old_participants`) supplies `old_signing_key = Some(share)`, execution proceeds to `do_reshare`:

```rust
// src/dkg.rs  lines 611-620
let intersection = old_participants.intersection(&participants);
let secret = old_signing_key
    .map(|x_i| {
        intersection
            .lagrange::<C>(me)
            .map(|lambda| lambda * x_i.to_scalar())
    })
    .transpose()?
    .unwrap_or_else(<C::Group as Group>::Field::zero);
``` [2](#0-1) 

Because `me` is absent from `old_participants`, it is also absent from `intersection`. The `lagrange` function computes the Lagrange coefficient for an arbitrary point outside the set — a well-defined, non-zero scalar — so the call succeeds and `secret` is non-zero.

`do_keyshare` is then called with this non-zero `secret` and `old_reshare_package = Some(...)`. Its very first action is:

```rust
// src/dkg.rs  lines 354-355
let (old_verification_key, old_participants) =
    assert_keyshare_inputs(me, &secret, old_reshare_package)?;
``` [3](#0-2) 

Inside `assert_keyshare_inputs`:

```rust
// src/dkg.rs  lines 39-44
} else {
    //  return error if me is part of the old participants set
    if !old_participants.contains(me) {
        return Err(ProtocolError::AssertionFailed(
            format!("{me:?} is running Resharing with a non-zero share but does not belong to the old participant set")));
    }
}
``` [4](#0-3) 

The check fires immediately — **before any network message is sent** — and returns `ProtocolError::AssertionFailed`. The malicious participant's protocol instance terminates without ever broadcasting its Round-1 session ID or any subsequent message.

Every other participant has already allocated a `ParticipantMap` slot for this participant and is blocked in `recv_from_others` waiting for its contribution. Because the library is documented to wait indefinitely:

> *"All our public functions … are designed to wait indefinitely for the expected messages."* [5](#0-4) 

the reshare is permanently stalled for all honest parties.

---

### Impact Explanation

**High — Permanent denial of reshare for honest parties.**

A single malicious new participant can abort the entire reshare ceremony for all honest parties by supplying a non-`None` signing key. No honest party can unilaterally recover; the only remedy is a caller-level timeout and a full protocol restart. This matches the allowed impact: *"Permanent denial of … reshare … for honest parties under valid protocol inputs and documented trust assumptions."*

---

### Likelihood Explanation

Medium. The attacker must be a participant in the new participant set but absent from `old_participants` — a role that exists in every reshare that adds new members. The exploit requires only passing a non-`None` value for `old_signing_key` when calling the public `reshare` API, which is trivially achievable by any new joiner acting maliciously.

---

### Recommendation

Add the symmetric guard that the comment already describes, immediately after the existing check:

```rust
// src/dkg.rs — inside assert_reshare_keys_invariants
if old_participants.contains(me) && old_signing_key.is_none() {
    return Err(InitializationError::BadParameters(format!(
        "party {me:?} is present in the old participant list but provided no share"
    )));
}
// ADD: reject the symmetric invalid case
if !old_participants.contains(me) && old_signing_key.is_some() {
    return Err(InitializationError::BadParameters(format!(
        "party {me:?} is not in the old participant list but provided a share"
    )));
}
``` [6](#0-5) 

This ensures the invariant is enforced at initialization time, before any network activity begins, consistent with the existing comment and the pattern used for the opposite case.

---

### Proof of Concept

```
1. Run keygen with participants [P1, P2, P3], threshold 2.
2. Begin reshare to new participant set [P1, P2, P3, P4_malicious].
3. P4_malicious (not in old_participants) calls reshare(..., old_signing_key = Some(arbitrary_share), ...).
4. assert_reshare_keys_invariants passes — no error.
5. do_reshare computes intersection.lagrange(P4_malicious) → non-zero λ.
   secret = λ * arbitrary_share.to_scalar()  (non-zero).
6. do_keyshare is entered; assert_keyshare_inputs fires:
   !old_participants.contains(P4_malicious) && secret != 0  → ProtocolError::AssertionFailed.
7. P4_malicious emits zero protocol messages.
8. P1, P2, P3 block forever in recv_from_others waiting for P4_malicious's Round-1 broadcast.
   Reshare is permanently stalled.
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

**File:** src/dkg.rs (L354-355)
```rust
    let (old_verification_key, old_participants) =
        assert_keyshare_inputs(me, &secret, old_reshare_package)?;
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

**File:** src/dkg.rs (L661-668)
```rust
    // Step 1.1
    // if me is not in the old participant set then ensure that old_signing_key is None
    if old_participants.contains(me) && old_signing_key.is_none() {
        return Err(InitializationError::BadParameters(format!(
            "party {me:?} is present in the old participant list but provided no share"
        )));
    }
    Ok((participants, old_participants))
```

**File:** README.md (L165-172)
```markdown
* All our public functions that involve network interactions, such as `keygen`,
  `reshare`, `sign`, and `ckd`, are designed to wait indefinitely for the
  expected messages. For instance, if a message needed to proceed is never
  received, the function will enter an infinite wait loop. This behavior is
  intentional, allowing the caller to determine how long to wait in each
  situation. Consequently, **the caller is responsible** for managing potential
  issues, such as implementing timeouts or other mechanisms to prevent functions
  from running indefinitely.
```
