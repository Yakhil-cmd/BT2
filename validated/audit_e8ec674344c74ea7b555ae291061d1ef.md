### Title
Missing Threshold Participant Count Validation in CKD Protocol Allows Corrupted Key Derivation Output - (File: src/confidential_key_derivation/protocol.rs)

### Summary
The `ckd()` function in the Confidential Key Derivation protocol does not accept a `threshold` parameter and performs no check that the number of participating parties meets the minimum reconstruction threshold established during DKG. A malicious coordinator can invoke the protocol with a sub-threshold participant set, causing the Lagrange interpolation to produce a wrong aggregate secret, delivering a corrupted derived key to the client.

### Finding Description

The `ckd()` entry-point validates only that:
- `participants.len() >= 2`
- no duplicates
- `me` and `coordinator` are in the list [1](#0-0) 

No threshold parameter is accepted and no check of the form `participants.len() >= threshold` is performed. Compare this with every other protocol in the library:

- OT-based ECDSA `sign()` checks `participants.len() < threshold` → `NotEnoughParticipantsForThreshold` [2](#0-1) 
- FROST `assert_sign_inputs()` checks `threshold.value() > participants.len()` → `ThresholdTooLarge` [3](#0-2) 
- DKG `assert_key_invariants()` checks both `threshold > participants.len()` and `threshold < 2` [4](#0-3) 

The CKD protocol is the only public entry-point that omits this guard entirely.

The cryptographic consequence is direct. Inside `compute_signature_share`, each party computes its Lagrange coefficient over the **current** participant list and multiplies it by its private share:

```
lambda_i = lagrange(participants, me)
norm_big_c = (x_i * H(pk, app_id) + y_i * A) * lambda_i
``` [5](#0-4) 

The coordinator then sums all `norm_big_c` values: [6](#0-5) 

For the sum to equal `msk * H(pk, app_id)` (the correct derived key), the Lagrange interpolation must be performed over a set of at least `threshold` parties. If fewer than `threshold` parties participate, the Lagrange coefficients are computed over the wrong polynomial evaluation points and the sum does not reconstruct `msk`. The output `CKDOutput` is silently wrong — no error is raised.

Because `KeygenOutput` stores only `public_key` and `private_share` (no threshold field), the `ckd()` function has no internal means to recover the threshold and enforce the check: [7](#0-6) 

### Impact Explanation

**High — Corruption of CKD outputs so honest parties accept unusable cryptographic outputs.**

A client who requests confidential key derivation receives a `CKDOutput` whose `unmask()` call yields a value that is not `msk * H(pk, app_id)`. The client has no way to detect this: the protocol completes without error, the output is structurally valid, but the derived key is cryptographically wrong. Any downstream use of that key (encryption, authentication, asset control) silently fails or produces attacker-influenced material.

### Likelihood Explanation

**Medium.** The attack requires a malicious or compromised coordinator who can convince all signing participants to use a participant list smaller than the DKG threshold. In deployments where the coordinator role is not fully trusted (which is the documented use-case — TEEs, decentralized asset management), this is a realistic threat. No cryptographic break is needed; only the ability to supply a short participant list to `ckd()`.

### Recommendation

Add a `threshold` parameter to `ckd()` and enforce the check before the protocol starts:

```rust
pub fn ckd(
    participants: &[Participant],
    coordinator: Participant,
    me: Participant,
    threshold: impl Into<ReconstructionLowerBound>,  // add this
    key_pair: KeygenOutput,
    app_id: impl Into<AppId>,
    app_pk: PublicKey,
    rng: impl CryptoRngCore + Send + 'static,
) -> Result<impl Protocol<Output = CKDOutputOption>, InitializationError> {
    let threshold = usize::from(threshold.into());

    if participants.len() < 2 {
        return Err(InitializationError::NotEnoughParticipants {
            participants: participants.len(),
        });
    }

    // Analog to the missing check: ensure enough parties to reconstruct msk
    if participants.len() < threshold {
        return Err(InitializationError::NotEnoughParticipantsForThreshold {
            threshold,
            participants: participants.len(),
        });
    }
    // ... rest of existing checks
}
```

This mirrors the pattern already used in `assert_key_invariants`, `assert_sign_inputs`, and the OT-based ECDSA `sign()` function.

### Proof of Concept

1. Run DKG with `participants = [A, B, C, D, E]`, `threshold = 3`. Each party holds a share `x_i` of `msk`.
2. Coordinator instructs all parties to call `ckd()` with `participants = [A, B]` (only 2, below threshold 3). The call succeeds — no error is returned.
3. Each of A and B computes `lambda_i` for the 2-element set `{A, B}`. These Lagrange coefficients are wrong for reconstructing `msk` (they are correct only for a degree-1 polynomial, not the degree-2 polynomial used in DKG).
4. The coordinator sums the two `norm_big_c` values and returns a `CKDOutput` whose `unmask(app_sk)` yields `wrong_value * H(pk, app_id)` where `wrong_value ≠ msk`.
5. The client receives a structurally valid but cryptographically incorrect derived key with no indication of failure.

### Citations

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

**File:** src/confidential_key_derivation/protocol.rs (L176-181)
```rust
    // Compute  λi := λi(0)
    let lambda_i = participants.lagrange::<BLS12381SHA256>(me)?;
    // Normalize Y and C into  (λi . Y , λi . C)
    let norm_big_y = big_y * lambda_i;
    let norm_big_c = big_c * lambda_i;
    Ok((norm_big_y, norm_big_c))
```

**File:** src/confidential_key_derivation/protocol.rs (L184-210)
```rust
#[cfg(test)]
mod test {
    use super::*;
    use crate::confidential_key_derivation::{
        ciphersuite::{hash_to_curve, G2Projective},
        hash_app_id_with_pk, SigningShare, VerifyingKey,
    };
    use crate::test_utils::{
        check_one_coordinator_output, generate_participants, run_protocol, GenProtocol,
        MockCryptoRng,
    };
    use rand::{seq::SliceRandom as _, RngCore, SeedableRng};

    #[test]
    fn test_hash2curve() {
        let app_id = b"Hello Near";
        let app_id_same = b"Hello Near";
        let pt1 = hash_to_curve(&AppId::try_from(app_id).unwrap());
        let pt2 = hash_to_curve(&AppId::try_from(app_id_same).unwrap());
        assert_eq!(pt1, pt2);

        let app_id = b"Hello Near!";
        let pt2 = hash_to_curve(&AppId::try_from(app_id).unwrap());
        assert_ne!(pt1, pt2);
    }

    #[test]
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
