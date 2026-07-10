### Title
Incomplete Conditional Guard in `assert_reshare_keys_invariants` Allows New Participant with Non-None Signing Key to Bypass Validation, Causing Reshare Protocol Denial of Service — (File: src/dkg.rs)

---

### Summary

`assert_reshare_keys_invariants` in `src/dkg.rs` contains an incomplete conditional check that validates only one of two symmetric invalid-input cases. It correctly rejects an old participant who supplies no signing key, but it fails to reject the symmetric case: a new participant (absent from `old_participants`) who supplies a non-None signing key. A malicious new participant exploits this gap to pass the public validation gate, enter `do_reshare`, and cause the protocol future to abort before emitting any messages — leaving every honest participant's protocol instance blocked indefinitely waiting for messages that never arrive.

---

### Finding Description

**Root cause — `src/dkg.rs`, lines 661–667:**

```rust
// Step 1.1
// if me is not in the old participant set then ensure that old_signing_key is None
if old_participants.contains(me) && old_signing_key.is_none() {
    return Err(InitializationError::BadParameters(format!(
        "party {me:?} is present in the old participant list but provided no share"
    )));
}
```

The code comment explicitly states the intended invariant — *"if me is NOT in the old participant set then ensure that old_signing_key is None"* — but the implemented guard checks the **opposite** case only: old participant + absent key. The symmetric case — new participant + present key — is never checked. The missing guard is:

```rust
if !old_participants.contains(me) && old_signing_key.is_some() {
    return Err(InitializationError::BadParameters(format!(
        "party {me:?} is not in the old participant list but provided a share"
    )));
}
```

**End-to-end exploit path:**

1. Malicious new participant `P_new` (not in `old_participants`) calls `reshare()` with `old_signing_key = Some(x_i)` for any non-None value.
2. `assert_reshare_keys_invariants` evaluates `old_participants.contains(P_new) && old_signing_key.is_none()` → `false && false` → **no error returned; `Ok` is returned**.
3. `reshare()` proceeds to call `do_reshare()` with `old_signing_key = Some(x_i)`.
4. Inside `do_reshare()` (`src/dkg.rs`, lines 611–620):
   ```rust
   let intersection = old_participants.intersection(&participants);
   let secret = old_signing_key
       .map(|x_i| {
           intersection.lagrange::<C>(me)
               .map(|lambda| lambda * x_i.to_scalar())
       })
       .transpose()?
       .unwrap_or_else(<C::Group as Group>::Field::zero);
   ```
   `P_new` is absent from `intersection`. However, `ParticipantList::lagrange` (`src/participants.rs`, lines 151–159) computes a Lagrange coefficient for any scalar `p` relative to the identifier list — it does **not** require `p` to be a member of the list. The computation succeeds and returns a non-zero scalar. `secret` becomes `non_zero_lambda * x_i.to_scalar()` — a non-zero, cryptographically meaningless value.
5. `do_keyshare()` is called with this non-zero `secret` and `old_reshare_package = Some(...)`.
6. `assert_keyshare_inputs()` (`src/dkg.rs`, lines 23–55) catches the inconsistency:
   ```rust
   } else {
       // return error if me is part of the old participants set
       if !old_participants.contains(me) {
           return Err(ProtocolError::AssertionFailed(
               format!("{me:?} is running Resharing with a non-zero share but does not belong to the old participant set")));
       }
   }
   ```
   `P_new` is not in `old_participants` and `secret` is non-zero → `ProtocolError::AssertionFailed` is returned.
7. The protocol future for `P_new` terminates immediately, **before sending any messages**.
8. Every other honest participant's protocol instance is now blocked waiting for Round 1 broadcast messages from `P_new` that will never arrive, causing the entire reshare to stall.

---

### Impact Explanation

The reshare protocol is permanently stalled for all honest parties in that session. Because `P_new`'s future aborts before emitting any network messages, honest participants have no signal to abort — they wait indefinitely (or until an external timeout). The `assert_reshare_keys_invariants` function is the documented public validation gate for reshare inputs; its false-positive `Ok` return misleads callers into believing the protocol will succeed, and the failure surfaces only as an opaque internal `ProtocolError` rather than an `InitializationError`, making it harder to diagnose and retry correctly. This matches **High: Permanent denial of reshare for honest parties**.

---

### Likelihood Explanation

Any participant included in the new participant set who is absent from the old participant set can trigger this by supplying any non-None `SigningShare` value. No special privilege, leaked key, or cryptographic break is required — only the ability to call the public `reshare()` API with a crafted argument.

---

### Recommendation

Add the missing symmetric guard immediately after the existing check in `assert_reshare_keys_invariants`:

```rust
// Existing check
if old_participants.contains(me) && old_signing_key.is_none() {
    return Err(InitializationError::BadParameters(format!(
        "party {me:?} is present in the old participant list but provided no share"
    )));
}
// Missing symmetric check
if !old_participants.contains(me) && old_signing_key.is_some() {
    return Err(InitializationError::BadParameters(format!(
        "party {me:?} is not in the old participant list but provided a share"
    )));
}
```

This makes the public validation gate consistent with the internal `assert_keyshare_inputs` check and with the comment that already documents the intended invariant.

---

### Proof of Concept

```
Setup:
  old_participants = [P1, P2, P3], old_threshold = 2
  new_participants = [P1, P2, P3, P_new]

P_new calls:
  reshare(
      old_participants = [P1, P2, P3],
      old_threshold    = 2,
      old_signing_key  = Some(<any SigningShare>),  // P_new is NOT in old set
      old_public_key   = <valid key>,
      new_participants = [P1, P2, P3, P_new],
      new_threshold    = 2,
      me               = P_new,
      rng              = ...,
  )

Result:
  assert_reshare_keys_invariants → Ok  (false positive)
  do_reshare → do_keyshare → assert_keyshare_inputs → ProtocolError::AssertionFailed
  P_new's future aborts before sending any messages.
  P1, P2, P3 block indefinitely waiting for P_new's Round 1 broadcast.
  Reshare session fails for all honest parties.
``` [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3)

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

**File:** src/dkg.rs (L610-620)
```rust
    let threshold = threshold.into();
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

**File:** src/participants.rs (L151-159)
```rust
    pub fn lagrange<C: Ciphersuite>(&self, p: Participant) -> Result<Scalar<C>, ProtocolError> {
        let p = p.scalar::<C>();
        let identifiers: Vec<Scalar<C>> = self
            .participants()
            .iter()
            .map(Participant::scalar::<C>)
            .collect();
        Ok(compute_lagrange_coefficient::<C>(&identifiers, &p, None)?.0)
    }
```
