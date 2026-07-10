### Title
Missing Threshold Lower-Bound Check in CKD Protocol Allows Coordinator to Corrupt Derived Key Output - (`File: src/confidential_key_derivation/protocol.rs`)

### Summary

The `ckd()` function in `src/confidential_key_derivation/protocol.rs` does not validate that the number of participants is at or above the DKG reconstruction threshold. A malicious coordinator can invoke the CKD protocol with fewer participants than the threshold, causing the Lagrange interpolation to reconstruct a wrong value instead of the master secret key, producing a silently corrupted derived key that the app accepts as valid.

### Finding Description

The `ckd()` entry point validates only that `participants.len() >= 2` and that there are no duplicates. It does not accept a threshold parameter and does not check that `participants.len() >= threshold` (the `ReconstructionLowerBound` established during DKG). [1](#0-0) 

The core computation in `compute_signature_share` applies Lagrange coefficients over the supplied participant set: [2](#0-1) 

The coordinator then sums all normalized shares: [3](#0-2) 

For the sum `Σ λ_i(participants) · x_i` to equal `msk`, Lagrange interpolation requires `|participants| >= threshold`. When fewer participants than the threshold are used, the interpolation evaluates a different polynomial at zero — producing a value that is not `msk`. The resulting `C` is therefore not `msk · H(pk, app_id) + a·Y`, and the app's unmasked key `s = C − a·Y` is silently wrong.

Compare this with the FROST signing path, which correctly enforces the lower bound: [4](#0-3) 

The OT-based ECDSA signing path similarly enforces `participants.len() >= threshold`: [5](#0-4) 

The CKD path has no equivalent guard.

### Impact Explanation

A malicious coordinator calls `ckd()` with a participant list of size `k < threshold`. The protocol completes without error. The coordinator sends the app a `(Y, C)` pair where `C ≠ msk · H(pk, app_id) + a·Y`. The app computes `s = C − a·Y`, which is not the correct confidential derived key. The app accepts this wrong key as valid because there is no verification step that checks the output against the expected master public key. This is a **corruption of the CKD output**: honest parties accept an inconsistent cryptographic output derived from a sub-threshold participant set.

This maps directly to the allowed High impact: *"Corruption of DKG, reshare, refresh, presign, sign, or CKD outputs so honest parties accept inconsistent public keys, participant sets, transcripts, or unusable cryptographic outputs."*

### Likelihood Explanation

The `ckd()` API gives the coordinator full control over the `participants` slice. A malicious coordinator can trivially pass a list of size 2 (the minimum accepted) regardless of the actual DKG threshold. No cryptographic capability is required — only the ability to call the public API with a truncated participant list. The protocol produces no error and the app has no way to detect the corruption.

### Recommendation

1. Add a `threshold: ReconstructionLowerBound` parameter to `ckd()` (mirroring `assert_sign_inputs` in `src/frost/mod.rs`) and enforce `participants.len() >= threshold.value()` before proceeding.
2. Alternatively, store the threshold inside `KeygenOutput` so that `ckd()` can retrieve and validate it without requiring a separate parameter.
3. Add a test analogous to the FROST and ECDSA threshold-too-large tests that verifies `ckd()` rejects a participant list smaller than the DKG threshold.

### Proof of Concept

```
Setup:
  - DKG with 3 participants, threshold = 3 (all must participate)
  - Malicious coordinator calls ckd(&[p1, p2], coordinator=p1, ...)
    with only 2 participants instead of 3

Expected: InitializationError (participants < threshold)
Actual:   Protocol runs to completion; coordinator returns CKDOutput
          where C = λ1·x1·H(pk,app_id) + λ2·x2·H(pk,app_id) + a·Y
          (Lagrange over {p1,p2}, not over {p1,p2,p3})
          ≠ msk·H(pk,app_id) + a·Y

App computes: s = C − a·Y = (λ1·x1 + λ2·x2)·H(pk,app_id) ≠ msk·H(pk,app_id)
App accepts wrong key s silently.
``` [6](#0-5)

### Citations

**File:** src/confidential_key_derivation/protocol.rs (L44-57)
```rust
    let (mut norm_big_y, mut norm_big_c) =
        compute_signature_share(&participants, me, key_pair, app_id, app_pk, rng)?;

    // Receive everyone's inputs and add them together
    let waitpoint = chan.next_waitpoint();

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

**File:** src/confidential_key_derivation/protocol.rs (L176-181)
```rust
    // Compute  λi := λi(0)
    let lambda_i = participants.lagrange::<BLS12381SHA256>(me)?;
    // Normalize Y and C into  (λi . Y , λi . C)
    let norm_big_y = big_y * lambda_i;
    let norm_big_c = big_c * lambda_i;
    Ok((norm_big_y, norm_big_c))
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

**File:** src/ecdsa/ot_based_ecdsa/sign.rs (L57-63)
```rust
    // ensure number of participants during the signing phase is >= threshold
    if participants.len() < threshold {
        return Err(InitializationError::NotEnoughParticipantsForThreshold {
            threshold,
            participants: participants.len(),
        });
    }
```
