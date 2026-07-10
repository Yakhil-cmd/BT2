### Title
CKD Protocol Accepts Sub-Threshold Participant Sets, Producing Corrupted Derived Keys — (File: `src/confidential_key_derivation/protocol.rs`)

---

### Summary

The `ckd` function in `src/confidential_key_derivation/protocol.rs` does not accept or enforce a threshold parameter. Every other threshold operation in the library — `keygen`, `reshare`, `refresh`, FROST presign/sign, OT-based ECDSA presign/sign, and Robust ECDSA presign/sign — validates that the participant count meets the threshold. The CKD path only requires `participants.len() >= 2`. A malicious coordinator (or misconfigured honest caller) can invoke `ckd` with fewer participants than the threshold used during key generation, causing the Lagrange interpolation to reconstruct the wrong scalar, producing a corrupted confidential derived key that the coordinator silently accepts as valid.

---

### Finding Description

During key generation (`keygen`), the library enforces strict threshold invariants:

```rust
// src/dkg.rs  assert_key_invariants
if threshold > participants.len() {
    return Err(InitializationError::ThresholdTooLarge { ... });
}
if threshold < 2 {
    return Err(InitializationError::ThresholdTooSmall { ... });
}
``` [1](#0-0) 

The resulting secret shares are evaluations of a degree-`(threshold − 1)` polynomial. Correct reconstruction of the master secret `msk` via Lagrange interpolation requires **at least `threshold` shares**.

The CKD entry point, however, carries no threshold parameter and performs no such check:

```rust
pub fn ckd(
    participants: &[Participant],
    coordinator: Participant,
    me: Participant,
    key_pair: KeygenOutput,
    app_id: impl Into<AppId>,
    app_pk: PublicKey,
    rng: impl CryptoRngCore + Send + 'static,
) -> Result<impl Protocol<Output = CKDOutputOption>, InitializationError> {
    if participants.len() < 2 {
        return Err(InitializationError::NotEnoughParticipants { ... });
    }
    // ← no threshold check here
``` [2](#0-1) 

Inside `compute_signature_share`, each participant computes their Lagrange-weighted contribution:

```rust
let lambda_i = participants.lagrange::<BLS12381SHA256>(me)?;
let norm_big_y = big_y * lambda_i;
let norm_big_c = big_c * lambda_i;
``` [3](#0-2) 

The coordinator then sums all contributions:

```rust
for (_, participant_output) in
    recv_from_others::<CKDOutput>(&chan, waitpoint, &participants, me).await?
{
    norm_big_y += participant_output.big_y();
    norm_big_c += participant_output.big_c();
}
let ckd_output = CKDOutput::new(norm_big_y, norm_big_c);
Ok(Some(ckd_output))
``` [4](#0-3) 

When the participant set `S` has `|S| < threshold`, the Lagrange coefficients `λ_i(S)` are computed over the wrong (smaller) set. The sum `Σ λ_i(S) · x_i` evaluates the unique degree-`(|S|−1)` polynomial through those points at zero — not the original degree-`(threshold−1)` polynomial. The result is `wrong_key ≠ msk`, and the coordinator accepts `wrong_key · H(pk, app_id)` as the confidential derived key with no error or verification.

The `KeygenOutput` struct carries no threshold field, so the `ckd` caller has no in-band signal about the required minimum:

```rust
pub struct KeygenOutput<C: Ciphersuite> {
    pub private_share: SigningShare<C>,
    pub public_key: VerifyingKey<C>,
}
``` [5](#0-4) 

This is structurally identical to the governance bug: the standard path (`keygen`) enforces the threshold invariant, while the alternative path (`ckd`) silently drops it, allowing a sub-threshold participant set to produce an output that is accepted as valid.

---

### Impact Explanation

**High — Corruption of CKD outputs so honest parties accept unusable cryptographic outputs.**

When `|S| < threshold`, the coordinator receives and stores a derived key `wrong_key · H(pk, app_id)` that does not correspond to `msk`. Any downstream consumer (e.g., a TEE application) that decrypts or authenticates using this key will silently operate on the wrong secret. There is no error, no verification step, and no way for the coordinator to detect the corruption after the fact.

---

### Likelihood Explanation

The `ckd` function is a public API callable by any library user. A malicious coordinator controls the `participants` slice passed to `ckd`. They can trivially pass a list of size 2 (the only enforced minimum) regardless of the actual threshold. An honest but misconfigured caller who does not independently track the threshold (which is not stored in `KeygenOutput`) will make the same mistake silently. The attack requires no cryptographic capability — only the ability to call the public API with a short participant list.

---

### Recommendation

Add a `threshold: impl Into<ReconstructionLowerBound>` parameter to `ckd` (mirroring every other threshold operation in the library) and enforce:

```rust
if participants.len() < threshold.value() {
    return Err(InitializationError::NotEnoughParticipantsForThreshold {
        threshold: threshold.value(),
        participants: participants.len(),
    });
}
```

Alternatively, embed the threshold into `KeygenOutput` so callers always have access to the correct value without out-of-band bookkeeping.

---

### Proof of Concept

```
Setup:
  - Run keygen with participants = [P1, P2, P3, P4, P5], threshold = 5.
  - Each P_i holds share x_i of the degree-4 polynomial f, where f(0) = msk.

Attack:
  - Coordinator (P1) calls ckd(participants=[P1, P2], coordinator=P1, ...)
  - P2 also calls ckd(participants=[P1, P2], coordinator=P1, ...)
  - Lagrange coefficients are computed over {P1, P2} only.
  - Coordinator accumulates:
      wrong_key = λ_1({P1,P2})·x_1 + λ_2({P1,P2})·x_2  ≠  msk
  - Coordinator receives CKDOutput containing wrong_key·H(pk, app_id).
  - No error is raised; the output is accepted as valid.

Expected: msk · H(pk, app_id)
Actual:   wrong_key · H(pk, app_id)   (wrong_key is the evaluation at 0
          of the unique degree-1 line through (id_1, x_1) and (id_2, x_2))
```

### Citations

**File:** src/dkg.rs (L572-582)
```rust
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
```

**File:** src/confidential_key_derivation/protocol.rs (L50-57)
```rust
    for (_, participant_output) in
        recv_from_others::<CKDOutput>(&chan, waitpoint, &participants, me).await?
    {
        norm_big_y += participant_output.big_y();
        norm_big_c += participant_output.big_c();
    }
    let ckd_output = CKDOutput::new(norm_big_y, norm_big_c);
    Ok(Some(ckd_output))
```

**File:** src/confidential_key_derivation/protocol.rs (L66-101)
```rust
pub fn ckd(
    participants: &[Participant],
    coordinator: Participant,
    me: Participant,
    key_pair: KeygenOutput,
    app_id: impl Into<AppId>,
    app_pk: PublicKey,
    rng: impl CryptoRngCore + Send + 'static,
) -> Result<impl Protocol<Output = CKDOutputOption>, InitializationError> {
    // not enough participants
    if participants.len() < 2 {
        return Err(InitializationError::NotEnoughParticipants {
            participants: participants.len(),
        });
    }

    // kick out duplicates
    let Some(participants) = ParticipantList::new(participants) else {
        return Err(InitializationError::DuplicateParticipants);
    };

    // ensure my presence in the participant list
    if !participants.contains(me) {
        return Err(InitializationError::MissingParticipant {
            role: "self",
            participant: me,
        });
    }

    // ensure the coordinator is a participant
    if !participants.contains(coordinator) {
        return Err(InitializationError::MissingParticipant {
            role: "coordinator",
            participant: coordinator,
        });
    }
```

**File:** src/confidential_key_derivation/protocol.rs (L177-181)
```rust
    let lambda_i = participants.lagrange::<BLS12381SHA256>(me)?;
    // Normalize Y and C into  (λi . Y , λi . C)
    let norm_big_y = big_y * lambda_i;
    let norm_big_c = big_c * lambda_i;
    Ok((norm_big_y, norm_big_c))
```

**File:** src/lib.rs (L51-55)
```rust
pub struct KeygenOutput<C: Ciphersuite> {
    pub private_share: SigningShare<C>,
    #[zeroize[skip]]
    pub public_key: VerifyingKey<C>,
}
```
