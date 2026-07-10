### Title
Missing Validation in `assert_reshare_keys_invariants` Allows New Participant with Non-Zero Key to Pass Pre-Validation but Fail Protocol Execution, Causing Denial of Reshare - (File: `src/dkg.rs`)

---

### Summary

`assert_reshare_keys_invariants` in `src/dkg.rs` is missing the check that a participant **not** in the old participant set must supply `None` as `old_signing_key`. The complementary check **is** present in `assert_keyshare_inputs`, which runs inside the live protocol execution path. A malicious new participant can therefore pass pre-validation, have the protocol created and started, and then cause `assert_keyshare_inputs` to abort before any messages are sent — leaving every honest participant blocked indefinitely waiting for the first broadcast message that never arrives.

---

### Finding Description

**Pre-validation path — `assert_reshare_keys_invariants` (`src/dkg.rs` lines 638–669)**

```rust
// if me is not in the old participant set then ensure that old_signing_key is None
if old_participants.contains(me) && old_signing_key.is_none() {
    return Err(InitializationError::BadParameters(format!(
        "party {me:?} is present in the old participant list but provided no share"
    )));
}
```

The comment literally describes the **opposite** of what the code checks. The code guards against `me ∈ old_set ∧ key = None`, but the comment says it should also guard against `me ∉ old_set ∧ key = Some(…)`. That second guard is entirely absent. [1](#0-0) 

**Protocol-execution path — `assert_keyshare_inputs` (`src/dkg.rs` lines 23–55)**

```rust
} else {
    // return error if me is part of the old participants set
    if !old_participants.contains(me) {
        return Err(ProtocolError::AssertionFailed(
            format!("{me:?} is running Resharing with a non-zero share but does not belong to the old participant set")));
    }
}
```

This check **is** present and fires when `secret ≠ 0 ∧ me ∉ old_participants`. [2](#0-1) 

**How the secret becomes non-zero for a new participant who supplies a key**

In `do_reshare`, the secret is derived as:

```rust
let intersection = old_participants.intersection(&participants);
let secret = old_signing_key
    .map(|x_i| {
        intersection
            .lagrange::<C>(me)
            .map(|lambda| lambda * x_i.to_scalar())
    })
    .transpose()?
    .unwrap_or_else(<C::Group as Group>::Field::zero);
```

`ParticipantList::lagrange` computes a Lagrange coefficient for any point, not only for members of the list. When `me ∉ old_participants`, `me ∉ intersection`, yet `intersection.lagrange::<C>(me)` still returns a non-

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
