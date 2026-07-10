### Title
Missing Cross-Phase Participant-Set Validation in OT-Based ECDSA Presign Enables Unattributable Denial of Signing - (File: `src/ecdsa/ot_based_ecdsa/presign.rs`)

### Summary
The `presign()` function in the OT-based ECDSA scheme explicitly omits the validation that the presign participant set is a subset of the triple-generation participant set. A malicious participant can supply triple shares generated under a different participant set, causing the presign protocol to abort with an error that does not identify the responsible party. Honest participants cannot attribute the failure and cannot exclude the malicious participant, enabling sustained denial of signing.

### Finding Description
The orchestration specification (`docs/ecdsa/ot_based_ecdsa/orchestration.md`) mandates the subset relationship `P ⊇ P0 ⊇ P1 ⊇ P2` across key-generation, triple-generation, presigning, and signing phases. Specifically, the presign participant set `P1` must be a subset of the triple-generation participant set `P0`, and the threshold constraints `N1 ≥ t0 ≥ t` must hold. [1](#0-0) 

The `presign()` initialization function, however, contains an explicit comment acknowledging that this cross-phase check is omitted: [2](#0-1) 

The only cross-phase check that is performed is a threshold equality check between `args.threshold` and the thresholds stored in `args.triple0.1.threshold` / `args.triple1.1.threshold`. There is no check that the participant identities used during triple generation match those used during presigning.

The `TriplePub` struct stores only the public group elements and the threshold value — it does not record the participant set that generated the triple: [3](#0-2) 

Inside `do_presign`, the Lagrange coefficient `lambda_me` is computed over the **presign** participant set `P1`: [4](#0-3) 

If the triple shares were generated under a different participant set `P0 ≠ P1`, the Lagrange interpolation is computed over the wrong set. The resulting sum `e = Σ λ_j(P1) · e_j` will not equal the triple secret `e_secret = Σ λ_j(P0) · e_j`, causing the runtime check to fail: [5](#0-4) 

The error message `"received incorrect shares of kd"` is a global assertion over the aggregated sum. It does not identify which participant contributed the mismatched share. Honest parties receive only this opaque error and have no protocol-level mechanism to attribute the failure to a specific participant.

### Impact Explanation
A malicious participant who holds triple shares from a prior triple-generation session (with a different participant set) can inject those shares into a new presign session. Every honest participant's presign protocol instance will abort with an unattributable error. Because the error does not name the offending party, honest participants cannot identify and exclude the malicious participant. The malicious participant can repeat this across every presign attempt, permanently preventing the honest quorum from completing a presignature and therefore from producing any threshold signature. This maps to **High: Permanent denial of signing for honest parties**.

### Likelihood Explanation
The attacker must be a legitimate member of the signing group (a malicious participant) who possesses triple shares from a prior session with a different participant set. This is a realistic scenario in long-running deployments where participant sets evolve across resharing or refresh cycles, and stale triple material may be retained. No privileged access beyond membership in the signing group is required.

### Recommendation
- **Short term:** Add an explicit check in `presign()` that rejects calls where the presign participant set is not a subset of the participant set recorded in the triple's public data. This requires storing the generating participant set inside `TriplePub` at triple-generation time.
- **Long term:** Extend `TriplePub` to include a cryptographic binding (e.g., a hash of the sorted participant list and threshold) produced during `generate_triple`. The `presign()` initialization function should verify this binding against the supplied participant list before proceeding, analogous to how `assert_reshare_keys_invariants` validates cross-phase participant-set consistency for the DKG reshare path. [6](#0-5) 

### Proof of Concept
1. Participants `{A, B, C}` run `generate_triple` with threshold 2, producing `(TripleShare_A, TriplePub_ABC)`, `(TripleShare_B, TriplePub_ABC)`, `(TripleShare_C, TriplePub_ABC)`.
2. Later, participants `{A, B}` run a new presign session with threshold 2. Participant A (malicious) supplies `TripleShare_A` from step 1 and `TriplePub_ABC` as `args.triple0`. Participant B (honest) also supplies their share from step 1.
3. `presign()` passes all initialization checks: `participants.len() >= 2`, threshold equality between `args.threshold` and `TriplePub_ABC.threshold`, and `me ∈ participants`.
4. Inside `do_presign`, Lagrange coefficients are computed over `{A, B}` (not `{A, B, C}`). The aggregated `e = λ_A({A,B})·e_A + λ_B({A,B})·e_B` does not equal `e_secret = λ_A({A,B,C})·e_A + λ_B({A,B,C})·e_B + λ_C({A,B,C})·e_C`.
5. The check `big_e != e·G` fires, returning `ProtocolError::AssertionFailed("received incorrect shares of kd")` — with no participant attribution.
6. Participant A repeats this in every presign attempt. Participant B receives only the opaque error and cannot identify A as the cause, making the denial of signing persistent. [7](#0-6)

### Citations

**File:** docs/ecdsa/ot_based_ecdsa/orchestration.md (L40-57)
```markdown
&\mathcal{P} &\supseteq &\mathcal{P}_0 &\supseteq &\mathcal{P}_1 &\supseteq &\mathcal{P}_2\cr
&N &\geq &N_0 &\geq &N_1 & \geq &N_2\cr
&t &&t_0 &&t_1 &&t_2\cr
\end{matrix}
$$

Each phase has a different set of parties, with each subsequent phase
having a subset of the parties present in the previous one.
The size of each party set, $N_i$, can also vary.
The thresholds can also change, subject to the following conditions:

$$
\begin{aligned}
&N_0 \geq t\cr
&N_1 \geq t_0 \geq t\cr
&N_2 \geq t_1 \geq t
\end{aligned}
$$
```

**File:** src/ecdsa/ot_based_ecdsa/presign.rs (L38-47)
```rust
    // NOTE: We omit the check that the new participant set was present for
    // the triple generation, because presumably they need to have been present
    // in order to have shares.

    // Also check that we have enough participants to reconstruct shares.
    if args.threshold != args.triple0.1.threshold || args.threshold != args.triple1.1.threshold {
        return Err(InitializationError::BadParameters(
            "New threshold must match the threshold of both triples".to_string(),
        ));
    }
```

**File:** src/ecdsa/ot_based_ecdsa/presign.rs (L91-103)
```rust
    // linearize ki ei ai bi ci xi
    // Spec 1.1
    let lambda_me = participants.lagrange::<Secp256>(me)?;

    let k_prime_i = lambda_me * k_i;
    let e_i: Scalar = lambda_me * e_i;

    let a_prime_i = lambda_me * a_i;
    let b_prime_i = lambda_me * b_i;

    let big_x: ProjectivePoint = args.keygen_out.public_key.to_element();
    let private_share = args.keygen_out.private_share.to_scalar();
    let x_prime_i = lambda_me * private_share;
```

**File:** src/ecdsa/ot_based_ecdsa/presign.rs (L112-131)
```rust
    let mut e = e_i;

    for (_, e_j) in recv_from_others::<Scalar>(&chan, wait0, &participants, me).await? {
        if e_j.is_zero().into() {
            return Err(ProtocolError::AssertionFailed(
                "Received zero share of kd, indicating a triple wasn't available.".to_string(),
            ));
        }

        // Spec 1.4
        e += e_j;
    }

    // E =?= e*G
    // Spec 1.5
    if big_e != (ProjectivePoint::GENERATOR * e).to_affine() {
        return Err(ProtocolError::AssertionFailed(
            "received incorrect shares of kd".to_string(),
        ));
    }
```

**File:** src/ecdsa/ot_based_ecdsa/mod.rs (L22-34)
```rust
/// The arguments needed to create a presignature.
#[derive(Debug, Clone)]
pub struct PresignArguments {
    /// The first triple's public information, and our share.
    pub triple0: (TripleShare, TriplePub),
    /// Ditto, for the second triple.
    pub triple1: (TripleShare, TriplePub),
    /// The output of key generation, i.e. our share of the secret key, and the public key package.
    /// This is of type `KeygenOutput<Secp256K1Sha256>` from Frost implementation
    pub keygen_out: KeygenOutput,
    /// The desired threshold for the presignature, which must match the original threshold
    pub threshold: ReconstructionLowerBound,
}
```

**File:** src/dkg.rs (L638-668)
```rust
pub fn assert_reshare_keys_invariants<C: Ciphersuite>(
    participants: &[Participant],
    me: Participant,
    threshold: impl Into<ReconstructionLowerBound>,
    old_signing_key: Option<SigningShare<C>>,
    old_threshold: impl Into<ReconstructionLowerBound>,
    old_participants: &[Participant],
) -> Result<(ParticipantList, ParticipantList), InitializationError> {
    let threshold = usize::from(threshold.into());
    let old_threshold = usize::from(old_threshold.into());

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
