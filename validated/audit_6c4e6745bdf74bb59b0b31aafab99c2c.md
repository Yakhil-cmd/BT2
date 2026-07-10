### Title
Missing Non-Empty Validation of `old_participants` in `assert_reshare_keys_invariants` Enables Reshare Protocol Abort - (File: src/dkg.rs)

### Summary
`assert_reshare_keys_invariants` accepts an empty `old_participants` slice and a zero `old_threshold` without error. A malicious participant exploits this to bypass all old-participant invariants, contribute a zero secret to the reshare, and force the protocol to abort for all honest parties.

### Finding Description

`assert_reshare_keys_invariants` in `src/dkg.rs` validates the new participant set via `assert_key_invariants` (which enforces `len() >= 2`, threshold bounds, etc.) but applies no equivalent minimum-size check to `old_participants`: [1](#0-0) 

`ParticipantList::new(&[])` succeeds and returns `Some(empty list)` — it only returns `None` for duplicates: [2](#0-1) 

`ReconstructionLowerBound` is a plain `usize` wrapper with no minimum enforcement, so `ReconstructionLowerBound(0)` is a valid value: [3](#0-2) 

With `old_participants = &[]` and `old_threshold = 0`, the intersection check `0 < 0` is false (no error), and the `old_signing_key` guard is skipped because `old_participants.contains(me)` is false on an empty list: [4](#0-3) 

Validation passes and `do_reshare` is called. Because `old_signing_key = None` and the intersection of the empty old list with the new participants is empty, `secret` is set to the zero scalar: [5](#0-4) 

Inside `do_keyshare`, `assert_keyshare_inputs` checks whether a zero-secret participant belongs to the old set. With an empty `old_participants`, `old_participants.contains(me)` is false, so no error is raised and the malicious participant is silently treated as a "new joiner": [6](#0-5) 

The `generate_proof` flag is also false for the malicious participant (because `old.contains(me)` is false on the empty list), so they send `None` as their proof of knowledge: [7](#0-6) 

When honest participants verify the malicious participant's `None` proof, they use their own correct `old_participants` list. Since the malicious participant IS in the correct old set, `verify_proof_of_knowledge` returns `Err(MaliciousParticipant)` and honest parties abort: [8](#0-7) 

The malicious participant's own execution aborts at the public-key consistency check, because their zero-secret contribution shifts the aggregate commitment away from the old public key: [9](#0-8) 

### Impact Explanation

Every honest participant aborts the reshare with `MaliciousParticipant` or a public-key mismatch error. Because the malicious participant holds one of the required old key shares, they can repeat this attack on every reshare attempt, permanently preventing the honest parties from completing the reshare under the documented trust model (where each old participant is expected to contribute their share honestly).

**Impact: High — Permanent denial of resharing for honest parties.**

### Likelihood Explanation

Any participant who holds an old signing share and controls their own library invocation can trigger this by passing `old_participants = &[]` and `old_threshold = 0` to `reshare()`. No cryptographic capability or external compromise is required — only the ability to call the public API with crafted inputs.

### Recommendation

Add an explicit minimum-size guard for `old_participants` in `assert_reshare_keys_invariants`, mirroring the guard already applied to the new participant set:

```rust
// In assert_reshare_keys_invariants, after computing old_threshold:
if old_participants_slice.len() < 2 {
    return Err(InitializationError::NotEnoughParticipants {
        participants: old_participants_slice.len(),
    });
}
```

Additionally, enforce that `old_threshold >= 2` (consistent with the new-threshold lower bound enforced in `assert_key_invariants`):

```rust
if old_threshold < 2 {
    return Err(InitializationError::ThresholdTooSmall { threshold: old_threshold, min: 2 });
}
```

### Proof of Concept

```rust
// Malicious participant B calls reshare with empty old_participants and zero threshold.
// new_participants contains at least 2 honest parties (A and B).
let result = reshare::<SomeCiphersuite>(
    &[],                    // old_participants = empty — no validation error
    0usize,                 // old_threshold = 0 — passes intersection check (0 < 0 is false)
    None,                   // old_signing_key = None — skipped because empty list doesn't contain me
    honest_old_public_key,
    &[participant_a, participant_b],
    2usize,
    participant_b,
    rng,
);
// result is Ok(...) — validation passes despite invalid inputs.
// When the protocol runs:
//   - B contributes secret = 0 (zero scalar) instead of its Lagrange-weighted share.
//   - Honest participant A detects B sent None proof while being in the old set → aborts with MaliciousParticipant(B).
//   - B's own execution aborts with "new public key does not match old public key".
// Reshare is permanently denied as long as B repeats this on every attempt.
```

### Citations

**File:** src/dkg.rs (L30-45)
```rust
    if let Some((old_key, old_participants)) = old_reshare_package {
        if is_zero_secret {
            //  return error if me is not a purely new joiner to the participants set
            //  prevents accidentally calling keyshare with extremely old keyshares
            //  that have nothing to do with the current resharing
            if old_participants.contains(me) {
                return Err(ProtocolError::AssertionFailed(
                    format!("{me:?} is running Resharing with a zero share but does belong to the old participant set")));
            }
        } else {
            //  return error if me is part of the old participants set
            if !old_participants.contains(me) {
                return Err(ProtocolError::AssertionFailed(
                    format!("{me:?} is running Resharing with a non-zero share but does not belong to the old participant set")));
            }
        }
```

**File:** src/dkg.rs (L182-196)
```rust
    match proof_of_knowledge {
        // if participant did not send anything but he is actually an old participant
        None => {
            // if basic dkg or participant is old
            if old_participants.is_none_or(|p| p.contains(participant)) {
                return Err(ProtocolError::MaliciousParticipant(participant));
            }
            // since previous line did not abort, then we know participant is new indeed
            // check the commitment length is threshold - 1
            if commitment.coefficients().len() != threshold - 1 {
                return Err(ProtocolError::IncorrectNumberOfCommitments);
            }
            // nothing to verify
            Ok(())
        }
```

**File:** src/dkg.rs (L386-401)
```rust
    let generate_proof: bool = old_participants.as_ref().is_none_or(|old| old.contains(me));
    // Step 2.5 2.6 2.7
    let proof_of_knowledge = if generate_proof {
        Some(proof_of_knowledge(
            &session_id,
            &mut domain_separator,
            me,
            &secret_coefficients,
            &coefficient_commitment,
            rng,
        )?)
    } else {
        // increment domain separator to match the old participants
        domain_separator.increment();
        None
    };
```

**File:** src/dkg.rs (L489-496)
```rust
    if let Some(old_vk) = old_verification_key {
        // check the equality between the old key and the new key without failing the unwrap
        if old_vk != verifying_key {
            return Err(ProtocolError::AssertionFailed(
                "new public key does not match old public key".to_string(),
            ));
        }
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

**File:** src/dkg.rs (L649-668)
```rust
    let participants = assert_key_invariants(participants, me, threshold)?;

    let old_participants =
        ParticipantList::new(old_participants).ok_or(InitializationError::DuplicateParticipants)?;

    // Step 1.1
    if old_participants.intersection(&participants).len() < old_threshold {
        return Err(InitializationError::NotEnoughParticipantsForNewThreshold {
            threshold: old_threshold,
            participants: old_participants.intersection(&participants).len(),
        });
    }
    // Step 1.1
    // if me is not in the old participant set then ensure that old_signing_key is None
    if old_participants.contains(me) && old_signing_key.is_none() {
        return Err(InitializationError::BadParameters(format!(
            "party {me:?} is present in the old participant list but provided no share"
        )));
    }
    Ok((participants, old_participants))
```

**File:** src/participants.rs (L88-105)
```rust
    fn new_vec(mut participants: Vec<Participant>) -> Option<Self> {
        participants.sort();

        let indices: HashMap<_, _> = participants
            .iter()
            .enumerate()
            .map(|(p, x)| (*x, p))
            .collect();

        if indices.len() < participants.len() {
            return None;
        }

        Some(Self {
            participants,
            indices,
        })
    }
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
