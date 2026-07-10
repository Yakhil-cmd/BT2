### Title
Participant Set Mismatch Between Presign and Sign Phases Corrupts Signing Output — (`src/frost/mod.rs`, `src/frost/eddsa/sign.rs`, `src/frost/redjubjub/sign.rs`)

### Summary
The FROST-based EdDSA and RedJubjub signing protocols accept a `participants` list at the signing phase that is never validated against the participant identifiers embedded in the `PresignOutput.commitments_map`. A malicious coordinator can supply a signing participant set that differs from the presigning participant set, causing Lagrange coefficients to be computed over the wrong set of identifiers. This corrupts every honest participant's signature share, making aggregation impossible and permanently denying signing for that presignature.

### Finding Description

During presigning, each participant broadcasts its nonce commitments and the result is stored in `PresignOutput.commitments_map`, a `BTreeMap<Identifier<C>, SigningCommitments<C>>` keyed by the identifiers of the exact participants who ran the presign protocol. [1](#0-0) 

During presigning, the map is populated from exactly the participants who participated: [2](#0-1) 

At the signing phase, `assert_sign_inputs` validates the caller-supplied `participants` slice for basic sanity (size ≥ 2, self-inclusion, coordinator-inclusion, threshold bound), but performs **no cross-check** against the identifiers already committed in `presignature.commitments_map`: [3](#0-2) 

The four checks performed are: [4](#0-3) 

None of them compare `participants` to the keys of `commitments_map`. A caller (or a malicious coordinator who controls what `participants` slice each honest party receives) can therefore pass a set `P_sign ≠ P_presign` to the signing function.

In FROST, the Lagrange coefficient for participant `i` is computed over the set of identifiers present in the signing package's commitment map. If `P_sign` is a strict subset of `P_presign`, the Lagrange coefficients are computed over the wrong denominator product, producing signature shares `z_i` that are individually well-formed but collectively inconsistent — they cannot be aggregated into a valid signature for the committed public key.

### Impact Explanation

Every honest participant computes its signature share using Lagrange coefficients derived from the wrong participant set. The coordinator receives shares that are cryptographically inconsistent with one another and with the group commitment `R` that was fixed during presigning. Aggregation fails, and the presignature is permanently consumed (nonces must never be reused). This constitutes **corruption of signing outputs** and **permanent denial of signing** for honest parties holding valid key shares and a valid presignature.

**Impact: High** — matches "Corruption of … sign … outputs so honest parties accept … unusable cryptographic outputs" and "Permanent denial of signing … for honest parties under valid protocol inputs."

### Likelihood Explanation

**Likelihood: Low-to-Medium.** The coordinator role is a documented trust boundary in this library. A malicious coordinator who controls the `participants` argument passed to each signer's signing call can trivially trigger this by advertising a participant set that omits one or more presigners. No cryptographic capability is required — only the ability to supply a different slice to different participants, which is exactly what a coordinator does in the protocol's communication model.

### Recommendation

In `assert_sign_inputs` (or in the signing entry-points for EdDSA and RedJubjub), add a validation step that checks the caller-supplied `participants` set is in exact bijection with the identifier keys of `presignature.commitments_map`. Concretely:

1. Collect the set of `Participant` values derived from `commitments_map.keys()`.
2. Assert that this set equals the `ParticipantList` built from the supplied `participants` slice.
3. Return `InitializationError::BadParameters` if they differ.

This mirrors the pattern already used for other invariants (duplicate detection, self-inclusion, coordinator-inclusion) and closes the gap between the two independently-supplied participant sets.

### Proof of Concept

1. Run presigning with participants `{A, B, C}` (threshold = 2). Each party obtains a `PresignOutput` whose `commitments_map` has three entries keyed by `{id_A, id_B, id_C}`.
2. A malicious coordinator calls the signing entry-point for honest parties `A` and `B` with `participants = [A, B]` (omitting `C`).
3. `assert_sign_inputs` passes: `len = 2 ≥ 2`, self and coordinator are present, threshold ≤ 2.
4. Each of `A` and `B` computes its Lagrange coefficient `λ_i` over `{id_A, id_B}` instead of `{id_A, id_B, id_C}`, yielding a different scalar.
5. The resulting signature shares `z_A, z_B` are computed with wrong `λ` values relative to the committed group nonce `R` (which was fixed over all three participants' commitments during presign).
6. Aggregation produces a value that does not satisfy the verification equation under the group public key, and the presignature is irrecoverably spent. [1](#0-0) [3](#0-2)

### Citations

**File:** src/frost/mod.rs (L36-41)
```rust
#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub struct PresignOutput<C: Ciphersuite + Send + 'static> {
    /// The public nonce commitment.
    pub nonces: SigningNonces<C>,
    pub commitments_map: BTreeMap<Identifier<C>, SigningCommitments<C>>,
}
```

**File:** src/frost/mod.rs (L98-116)
```rust
    let mut commitments_map: BTreeMap<Identifier<C>, SigningCommitments<C>> = BTreeMap::new();

    // Creating two commitments and corresponding nonces
    let (nonces, commitments) = commit(&signing_share, &mut rng);
    commitments_map.insert(me.to_identifier()?, commitments);

    let commit_waitpoint = chan.next_waitpoint();
    // Sending the commitments to all
    chan.send_many(commit_waitpoint, &commitments)?;

    // Collecting the commitments
    for (from, commitment) in recv_from_others(&chan, commit_waitpoint, &participants, me).await? {
        commitments_map.insert(from.to_identifier()?, commitment);
    }

    Ok(PresignOutput {
        nonces,
        commitments_map,
    })
```

**File:** src/frost/mod.rs (L120-159)
```rust
pub fn assert_sign_inputs(
    participants: &[Participant],
    threshold: impl Into<ReconstructionLowerBound>,
    me: Participant,
    coordinator: Participant,
) -> Result<ParticipantList, InitializationError> {
    let threshold = threshold.into();
    if participants.len() < 2 {
        return Err(InitializationError::NotEnoughParticipants {
            participants: participants.len(),
        });
    }
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

    // validate threshold
    if threshold.value() > participants.len() {
        return Err(InitializationError::ThresholdTooLarge {
            threshold: threshold.value(),
            max: participants.len(),
        });
    }

    // ensure the coordinator is a participant
    if !participants.contains(coordinator) {
        return Err(InitializationError::MissingParticipant {
            role: "coordinator",
            participant: coordinator,
        });
    }
    Ok(participants)
```
