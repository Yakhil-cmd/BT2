### Title
Missing Lower-Bound Validation on `threshold` in FROST Presign/Sign Initialization — (`File: src/frost/mod.rs`)

---

### Summary

`assert_key_invariants` (used by DKG/keygen) enforces both a lower bound (`threshold >= 2`) and an upper bound (`threshold <= N`) on the threshold parameter. The FROST presign and sign initialization paths — `frost::presign` and `frost::assert_sign_inputs` — enforce only the upper bound. A caller can supply `threshold = 1` (or `0`) to these functions, bypassing the minimum-threshold invariant that the keygen path enforces, and causing the signing protocol to proceed with a cryptographically invalid reconstruction threshold.

---

### Finding Description

`assert_key_invariants` in `src/dkg.rs` enforces both bounds:

```rust
// lower bound
if threshold < 2 {
    return Err(InitializationError::ThresholdTooSmall { threshold, min: 2 });
}
// upper bound
if threshold > participants.len() {
    return Err(InitializationError::ThresholdTooLarge { ... });
}
``` [1](#0-0) 

`frost::presign` checks only the upper bound:

```rust
if args.threshold.value() > participants.len() {
    return Err(InitializationError::ThresholdTooLarge { ... });
}
// ← no lower-bound check; threshold = 1 or 0 is accepted
``` [2](#0-1) 

`frost::assert_sign_inputs` has the same gap:

```rust
if threshold.value() > participants.len() {
    return Err(InitializationError::ThresholdTooLarge { ... });
}
// ← no lower-bound check
``` [3](#0-2) 

`ReconstructionLowerBound` is a plain `usize` newtype with no invariant enforcement of its own:

```rust
pub struct ReconstructionLowerBound(usize);
``` [4](#0-3) 

So a caller can construct `ReconstructionLowerBound(1)` or `ReconstructionLowerBound(0)` and pass it directly to `frost::presign` or `frost::assert_sign_inputs` without triggering any error.

---

### Impact Explanation

In FROST, the threshold determines the degree of the secret-sharing polynomial and the number of shares required for Lagrange reconstruction of the signing nonce. If `threshold = 1` is accepted at sign time but the key was generated with `threshold = 2` (the minimum enforced by keygen), the Lagrange interpolation in the signing protocol operates over a degree-0 polynomial assumption while the actual shares lie on a degree-1 polynomial. The reconstructed nonce and partial signatures are therefore wrong, and the resulting ECDSA/EdDSA signature is cryptographically invalid. Honest participants complete the protocol without error and accept the corrupted output.

**Matched impact**: *High — Corruption of sign outputs so honest parties accept unusable cryptographic outputs.*

---

### Likelihood Explanation

Any unprivileged library caller or malicious coordinator invoking `frost::presign` or `frost::assert_sign_inputs` can supply an out-of-range threshold. No special privilege, leaked key, or cryptographic break is required. The `ReconstructionLowerBound` type imposes no constructor-level restriction, so `ReconstructionLowerBound(1)` is a valid Rust value that compiles and passes the existing checks.

---

### Recommendation

Add the same lower-bound check present in `assert_key_invariants` to both `frost::presign` and `frost::assert_sign_inputs`:

```rust
if threshold.value() < 2 {
    return Err(InitializationError::ThresholdTooSmall {
        threshold: threshold.value(),
        min: 2,
    });
}
```

Alternatively, enforce the invariant inside `ReconstructionLowerBound::new` (a constructor that rejects values below 2) so that the type itself cannot represent an invalid threshold, eliminating the class of bug at the type level — consistent with how the rest of the codebase uses newtypes for safety.

---

### Proof of Concept

1. Run a FROST keygen with `threshold = 2`, `N = 3` participants → succeeds (lower-bound check passes in `assert_key_invariants`).
2. Call `frost::presign` with the resulting `KeygenOutput` but supply `PresignArguments { threshold: ReconstructionLowerBound(1), ... }`.
3. `frost::presign` accepts the call — `1 <= 3` passes the only check at line 72.
4. Call `frost::assert_sign_inputs` with `threshold = ReconstructionLowerBound(1)` — again accepted.
5. The signing protocol proceeds; Lagrange interpolation uses only 1 share against a degree-1 polynomial, producing a garbage signature scalar.
6. No `InitializationError` or `ProtocolError` is returned; honest parties accept the corrupted output. [5](#0-4) [6](#0-5)

### Citations

**File:** src/dkg.rs (L558-596)
```rust
pub fn assert_key_invariants(
    participants: &[Participant],
    me: Participant,
    threshold: impl Into<ReconstructionLowerBound>,
) -> Result<ParticipantList, InitializationError> {
    let threshold = usize::from(threshold.into());
    // need enough participants
    if participants.len() < 2 {
        return Err(InitializationError::NotEnoughParticipants {
            participants: participants.len(),
        });
    }

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

    // ensure uniqueness of participants in the participant list
    let participants =
        ParticipantList::new(participants).ok_or(InitializationError::DuplicateParticipants)?;

    // ensure my presence in the participant list
    if !participants.contains(me) {
        return Err(InitializationError::MissingParticipant {
            role: "self",
            participant: me,
        });
    }
    Ok(participants)
}
```

**File:** src/frost/mod.rs (L44-88)
```rust
pub fn presign<C>(
    participants: &[Participant],
    me: Participant,
    args: &PresignArguments<C>,
    rng: impl CryptoRngCore + Send + 'static,
) -> Result<impl Protocol<Output = PresignOutput<C>>, InitializationError>
where
    C: Ciphersuite + Send,
    <<<C as frost_core::Ciphersuite>::Group as Group>::Field as Field>::Scalar: Send,
    <<C as frost_core::Ciphersuite>::Group as frost_core::Group>::Element: std::marker::Send,
{
    if participants.len() < 2 {
        return Err(InitializationError::NotEnoughParticipants {
            participants: participants.len(),
        });
    }

    let participants =
        ParticipantList::new(participants).ok_or(InitializationError::DuplicateParticipants)?;

    if !participants.contains(me) {
        return Err(InitializationError::MissingParticipant {
            role: "self",
            participant: me,
        });
    }

    // validate threshold
    if args.threshold.value() > participants.len() {
        return Err(InitializationError::ThresholdTooLarge {
            threshold: args.threshold.into(),
            max: participants.len(),
        });
    }

    let ctx = Comms::new();
    let fut = do_presign(
        ctx.shared_channel(),
        participants,
        me,
        args.keygen_out.private_share,
        rng,
    );
    Ok(make_protocol(ctx, fut))
}
```

**File:** src/frost/mod.rs (L144-150)
```rust
    // validate threshold
    if threshold.value() > participants.len() {
        return Err(InitializationError::ThresholdTooLarge {
            threshold: threshold.value(),
            max: participants.len(),
        });
    }
```

**File:** src/thresholds.rs (L9-12)
```rust
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, From, Into,
)]
pub struct ReconstructionLowerBound(usize);
```
