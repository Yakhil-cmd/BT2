### Title
One-Sided Participant/Key Validation in `assert_reshare_keys_invariants` Allows New Participant with Signing Key to Abort Reshare for All Honest Parties - (File: src/dkg.rs)

### Summary

`assert_reshare_keys_invariants` in `src/dkg.rs` validates only one of two symmetric participant/key cases. It rejects an old participant who provides no key, but silently accepts a new participant (not in the old set) who provides a signing key. This passes initialization, then causes a runtime `ProtocolError` inside `do_reshare` before any messages are sent, leaving all other honest participants permanently blocked waiting for messages that never arrive.

### Finding Description

`assert_reshare_keys_invariants` is the initialization guard for both `reshare()` and `refresh()`. It is supposed to enforce two symmetric invariants:

1. An old participant **must** supply their signing key.
2. A new participant **must not** supply a signing key.

The code at line 663 only enforces invariant 1:

```rust
// if me is not in the old participant set then ensure that old_signing_key is None
if old_participants.contains(me) && old_signing_key.is_none() {
    return Err(InitializationError::BadParameters(format!(
        "party {me:?} is present in the old participant list but provided no share"
    )));
}
```

The comment literally describes invariant 2 ("if me is **not** in the old participant set then ensure that old_signing_key is None"), but the code implements the opposite condition. The missing guard is:

```rust
if !old_participants.contains(me) && old_signing_key.is_some() {
    return Err(InitializationError::BadParameters(...));
}
```

Without it, a new participant `P_new` (not in `old_participants`) who passes `old_signing_key = Some(key)` clears initialization and receives `Ok(protocol)`. When the protocol is first poked, `do_reshare` executes:

```rust
let intersection = old_participants.intersection(&participants);
let secret = old_signing_key
    .map(|x_i| {
        intersection
            .lagrange::<C>(me)          // P_new is not in intersection → Err(InvalidIndex)
            .map(|lambda| lambda * x_i.to_scalar())
    })
    .transpose()?                       // propagates the error immediately
    .unwrap_or_else(...);
```

Because `P_new` is absent from `intersection`, `lagrange` returns `Err(ProtocolError::InvalidIndex)`. The protocol terminates with an error before sending a single message. Every other honest participant is now blocked in `do_keyshare` waiting for session-id broadcasts and subsequent rounds from `P_new` that will never arrive.

Note that `assert_keyshare_inputs` inside `do_keyshare` does check both cases correctly, but it is never reached because `do_reshare` fails first.

### Impact Explanation

All honest participants who have already started their `reshare` protocol instances are stuck indefinitely waiting for messages from the failing participant. There is no built-in timeout or abort signal in the protocol loop. This constitutes **permanent denial of the reshare operation** for all honest parties, matching the allowed High impact: *"Permanent denial of signing, key generation, reshare, refresh, or CKD for honest parties under valid protocol inputs and documented trust assumptions."*

### Likelihood Explanation

Any participant who is newly joining a reshare (i.e., not in `old_participants`) and who calls `reshare()` with a non-`None` `old_signing_key` triggers this path. This can be:
- A misconfigured honest node (accidental).
- A malicious new joiner deliberately supplying a fabricated key to abort the reshare round.

The entry point is the public `reshare()` API in `src/lib.rs`, reachable by any library caller. No special privileges are required beyond being listed in `new_participants`.

### Recommendation

Add the symmetric check to `assert_reshare_keys_invariants`:

```rust
// if me is not in the old participant set then ensure that old_signing_key is None
if old_participants.contains(me) && old_signing_key.is_none() {
    return Err(InitializationError::BadParameters(format!(
        "party {me:?} is present in the old participant list but provided no share"
    )));
}
// NEW: if me is a new joiner, it must not supply an old signing key
if !old_participants.contains(me) && old_signing_key.is_some() {
    return Err(InitializationError::BadParameters(format!(
        "party {me:?} is not in the old participant list but provided a share"
    )));
}
```

### Proof of Concept

```
1. Run DKG with participants [P1, P2, P3], threshold=2.
2. Introduce new participant P4 (not in old set).
3. P4 calls reshare(
       old_participants=[P1,P2,P3],
       old_threshold=2,
       old_signing_key=Some(<any SigningShare>),  // ← invalid but passes init
       old_public_key=<correct pub key>,
       new_participants=[P1,P2,P3,P4],
       new_threshold=3,
       me=P4,
       rng=...
   )
4. reshare() returns Ok(protocol) — assert_reshare_keys_invariants passes.
5. P1, P2, P3 start their own valid reshare protocol instances.
6. On first poke() of P4's protocol:
   - do_reshare computes intersection = {P1,P2,P3} ∩ {P1,P2,P3,P4} = {P1,P2,P3}
   - intersection.lagrange(P4) → Err(InvalidIndex)
   - protocol returns Err immediately, sends no messages
7. P1, P2, P3 are permanently blocked waiting for P4's Round 1 broadcast.
```

**Root cause**: [1](#0-0) 

**Missing symmetric case** (comment describes it, code omits it): [2](#0-1) 

**Runtime failure site in `do_reshare`**: [3](#0-2) 

**Public entry point**: [4](#0-3)

### Citations

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

**File:** src/lib.rs (L106-141)
```rust
pub fn reshare<C: Ciphersuite>(
    old_participants: &[Participant],
    old_threshold: impl Into<ReconstructionLowerBound> + Send + 'static,
    old_signing_key: Option<SigningShare<C>>,
    old_public_key: VerifyingKey<C>,
    new_participants: &[Participant],
    new_threshold: impl Into<ReconstructionLowerBound> + Copy + Send + 'static,
    me: Participant,
    rng: impl CryptoRngCore + Send + 'static,
) -> Result<impl Protocol<Output = KeygenOutput<C>>, InitializationError>
where
    Element<C>: Send,
    Scalar<C>: Send,
{
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
}
```
