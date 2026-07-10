### Title
Threshold Value Exceeding `u16::MAX` Causes Permanent Denial of Signing — (File: `src/frost/eddsa/sign.rs`, `src/frost/redjubjub/sign.rs`)

---

### Summary

Both FROST signing modules (`eddsa` and `redjubjub`) convert the `threshold` parameter from `usize` to `u16` inside `construct_key_package` when building the `KeyPackage` for the underlying frost library. The DKG validation layer (`assert_key_invariants`) imposes no upper bound of `u16::MAX` (65 535) on the threshold. A threshold value above 65 535 passes DKG without error but causes every subsequent signing call to fail permanently with a conversion error, permanently denying signing to all honest participants.

---

### Finding Description

`ReconstructionLowerBound` wraps a plain `usize` with no documented ceiling: [1](#0-0) 

`assert_key_invariants` only enforces `threshold >= 2` and `threshold <= participants.len()`: [2](#0-1) 

There is no check that `threshold <= u16::MAX`. Because `Participant` is a `u32`, a participant list of size > 65 535 is representable, so a threshold of, say, 70 000 passes all DKG guards and `do_keyshare` completes successfully.

At signing time, both `construct_key_package` implementations attempt a narrowing conversion:

**EdDSA (`src/frost/eddsa/sign.rs`):** [3](#0-2) 

**RedJubjub (`src/frost/redjubjub/sign.rs`):** [4](#0-3) 

`u16::try_from(70_000)` returns `Err`, which is mapped to `ProtocolError::Other(...)` and propagated. Every call to `sign_v1`, `sign_v2`, or `sign` (redjubjub) will fail at this point for every participant, with no recovery path.

---

### Impact Explanation

Once DKG completes with a threshold > 65 535, the resulting key material is permanently unusable for signing. No signing round can succeed because `construct_key_package` is called unconditionally by both the coordinator and every participant path before any cryptographic work is done. This constitutes **permanent denial of signing for all honest parties** under inputs that the API accepts without error.

---

### Likelihood Explanation

Requires a participant set larger than 65 535, which is operationally unrealistic for current deployments. However, the API surface accepts any `usize` threshold, documents no upper bound, and the DKG layer emits no error, so a misconfigured or adversarially-guided deployment could reach this state. The gap between what the API accepts and what signing can handle is the root cause.

---

### Recommendation

Add an explicit upper-bound guard in `assert_key_invariants` (or in a dedicated `assert_sign_inputs` check) before any protocol round begins:

```rust
if threshold > u16::MAX as usize {
    return Err(InitializationError::ThresholdTooLarge { threshold, max: u16::MAX as usize });
}
```

Alternatively, change `KeyPackage::new`'s `min_signers` argument to accept `usize` internally and perform the narrowing only at the frost-library boundary with a clear documented constraint.

---

### Proof of Concept

1. Call `keygen::<Ed25519Sha512>` with 70 000 participants and `threshold = 70_000`. `assert_key_invariants` passes; `do_keyshare` completes; all parties receive valid `KeygenOutput`.
2. Call `sign_v1` (or `sign_v2`) with the same 70 000 participants and `threshold = 70_000`.
3. Inside `construct_key_package`, `u16::try_from(70_000)` returns `Err`.
4. `ProtocolError::Other("threshold cannot be converted to u16")` is returned.
5. Every participant's signing future terminates with this error; no signature is ever produced. The key material is permanently locked out of use.

### Citations

**File:** src/thresholds.rs (L7-12)
```rust
pub struct MaxMalicious(usize);

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, From, Into,
)]
pub struct ReconstructionLowerBound(usize);
```

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

**File:** src/frost/eddsa/sign.rs (L360-368)
```rust
    Ok(KeyPackage::new(
        identifier,
        signing_share,
        verifying_share,
        *verifying_key,
        u16::try_from(threshold.value()).map_err(|_| {
            ProtocolError::Other("threshold cannot be converted to u16".to_string())
        })?,
    ))
```

**File:** src/frost/redjubjub/sign.rs (L249-257)
```rust
    let key_package = KeyPackage::new(
        identifier,
        signing_share,
        verifying_share,
        verifying_key,
        u16::try_from(threshold.value()).map_err(|_| {
            ProtocolError::Other("threshold cannot be converted to u16".to_string())
        })?,
    );
```
