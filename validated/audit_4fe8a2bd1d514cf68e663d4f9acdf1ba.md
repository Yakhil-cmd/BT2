### Title
CKD Coordinator Accepts Participant Contributions Without Validity Verification — (`File: src/confidential_key_derivation/protocol.rs`)

### Summary
In `do_ckd_coordinator`, the coordinator receives `(norm_big_y, norm_big_c)` group-element pairs from each participant via `recv_from_others` and blindly accumulates them into the final `CKDOutput` without any proof of correctness. A malicious participant can send arbitrary `G1` elements, corrupting the derived confidential key accepted by all honest parties.

### Finding Description
The CKD coordinator loop in `do_ckd_coordinator` (lines 50–55) receives each participant's contribution and immediately adds it to the running sums:

```rust
for (_, participant_output) in
    recv_from_others::<CKDOutput>(&chan, waitpoint, &participants, me).await?
{
    norm_big_y += participant_output.big_y();
    norm_big_c += participant_output.big_c();
}
``` [1](#0-0) 

Each participant is supposed to compute, in `compute_signature_share`:
- `norm_big_y = λ_i · y_i · G`
- `norm_big_c = λ_i · (x_i · H(pk ‖ app_id) + y_i · app_pk)` [2](#0-1) 

The coordinator performs no check that the received `(norm_big_y, norm_big_c)` is consistent with the sender's public key share or with any commitment. There is no zero-knowledge proof, no Pedersen commitment binding, and no identity-element guard on the received values. The `CKDOutput` struct itself is a plain pair of `ElementG1` values with no embedded validity invariant. [3](#0-2) 

Compare this with the DKG protocol, which requires every participant to supply a proof of knowledge for their polynomial commitment before any share is accepted: [4](#0-3) 

No equivalent verification exists in the CKD path.

### Impact Explanation
The final `CKDOutput` is used by the client to unmask the confidential key:

```
confidential_key = big_c_total − app_sk · big_y_total
``` [5](#0-4) 

If one malicious participant substitutes arbitrary `(big_y', big_c')` for their correct contribution, the coordinator computes:

```
big_y_total  = Σ_{honest} λ_i·y_i·G  +  big_y'
big_c_total  = Σ_{honest} λ_i·(x_i·H + y_i·A)  +  big_c'
```

The unmasked result is no longer `msk · H(pk ‖ app_id)`. The client receives and accepts a corrupted, unusable derived key with no indication that anything went wrong. This matches the allowed impact: **High — Corruption of CKD outputs so honest parties accept unusable cryptographic outputs**.

### Likelihood Explanation
Any single participant in the CKD session is an attacker-controlled entry point. The participant role requires no special privilege beyond being in the `participants` list. The malicious participant simply sends a crafted `CKDOutput` message instead of the honest one; the coordinator's `recv_from_others` loop accepts it unconditionally. No cryptographic assumption needs to be broken. [6](#0-5) 

### Recommendation
Require each participant to accompany their `(norm_big_y, norm_big_c)` with a non-interactive zero-knowledge proof of correct formation — specifically, a proof that `norm_big_c − norm_big_y · app_pk` lies on the line `λ_i · x_i · H(pk ‖ app_id)` relative to the participant's public key share. The coordinator must verify this proof before accumulating the contribution, analogous to how `verify_proof_of_knowledge` gates share acceptance in the DKG protocol. [7](#0-6) 

At minimum, reject contributions where either element is the group identity, mirroring the identity-element guard already present in the robust ECDSA presign path. [8](#0-7) 

### Proof of Concept
1. Honest participants `P1, P2, P3` run `ckd(...)` with `P1` as coordinator.
2. Malicious `P2` overrides its protocol implementation to send `CKDOutput { big_y: G1::identity(), big_c: G1::identity() }` to `P1` instead of the correct share.
3. `do_ckd_coordinator` receives the zeroed contribution and adds it: `norm_big_y += identity`, `norm_big_c += identity` — effectively dropping `P2`'s honest share from the sum.
4. The coordinator outputs `CKDOutput` whose `unmask(app_sk)` yields `Σ_{i≠2} λ_i · x_i · H(pk ‖ app_id)` instead of `msk · H(pk ‖ app_id)`.
5. The client derives and stores an incorrect confidential key with no error returned anywhere in the protocol.

### Citations

**File:** src/confidential_key_derivation/protocol.rs (L17-33)
```rust
fn do_ckd_participant(
    mut chan: SharedChannel,
    participants: &ParticipantList,
    coordinator: Participant,
    me: Participant,
    key_pair: &KeygenOutput,
    app_id: &AppId,
    app_pk: PublicKey,
    rng: &mut impl CryptoRngCore,
) -> Result<CKDOutputOption, ProtocolError> {
    let (norm_big_y, norm_big_c) =
        compute_signature_share(participants, me, key_pair, app_id, app_pk, rng)?;
    let waitpoint = chan.next_waitpoint();
    chan.send_private(waitpoint, coordinator, &(norm_big_y, norm_big_c))?;

    Ok(None)
}
```

**File:** src/confidential_key_derivation/protocol.rs (L50-55)
```rust
    for (_, participant_output) in
        recv_from_others::<CKDOutput>(&chan, waitpoint, &participants, me).await?
    {
        norm_big_y += participant_output.big_y();
        norm_big_c += participant_output.big_c();
    }
```

**File:** src/confidential_key_derivation/protocol.rs (L165-181)
```rust
    let big_y = ElementG1::generator() * y.0;

    // H(pk || app_id) when H is a random oracle
    let hash_point = hash_app_id_with_pk(&key_pair.public_key, app_id);

    // S <- x . H(app_id)
    let big_s = hash_point * private_share.to_scalar();

    // C <- S + y . A
    let big_c = big_s + app_pk * y.0;

    // Compute  λi := λi(0)
    let lambda_i = participants.lagrange::<BLS12381SHA256>(me)?;
    // Normalize Y and C into  (λi . Y , λi . C)
    let norm_big_y = big_y * lambda_i;
    let norm_big_c = big_c * lambda_i;
    Ok((norm_big_y, norm_big_c))
```

**File:** src/confidential_key_derivation/mod.rs (L32-57)
```rust
pub struct CKDOutput {
    big_y: ElementG1,
    big_c: ElementG1,
}

impl CKDOutput {
    pub fn new(big_y: ElementG1, big_c: ElementG1) -> Self {
        Self { big_y, big_c }
    }

    /// Outputs `big_y`
    pub fn big_y(&self) -> ElementG1 {
        self.big_y
    }

    /// Outputs `big_c`
    pub fn big_c(&self) -> ElementG1 {
        self.big_c
    }

    /// Takes a secret scalar and returns
    /// s <- C − a ⋅ Y = msk ⋅ H ( `app_id` )
    pub fn unmask(&self, secret_scalar: Scalar) -> Signature {
        self.big_c - self.big_y * secret_scalar
    }
}
```

**File:** src/dkg.rs (L172-218)
```rust
fn verify_proof_of_knowledge<C: Ciphersuite>(
    session_id: &HashOutput,
    domain_separator: &mut DomainSeparator,
    threshold: ReconstructionLowerBound,
    participant: Participant,
    old_participants: Option<ParticipantList>,
    commitment: &VerifiableSecretSharingCommitment<C>,
    proof_of_knowledge: Option<&Signature<C>>,
) -> Result<(), ProtocolError> {
    let threshold = threshold.value();
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
        // now we know the proof is not none
        Some(proof_of_knowledge) => {
            // if participant sent something but he is actually a new participant
            if old_participants.is_some_and(|p| !p.contains(participant)) {
                return Err(ProtocolError::MaliciousParticipant(participant));
            }
            // since the previous did not abort, we know the participant is old or we are dealing with a dkg
            if commitment.coefficients().len() != threshold {
                return Err(ProtocolError::IncorrectNumberOfCommitments);
            }

            // creating an identifier as required by the syntax of verify_proof_of_knowledge of frost_core
            internal_verify_proof_of_knowledge(
                session_id,
                domain_separator,
                participant,
                commitment,
                proof_of_knowledge,
            )
        }
    }
}
```

**File:** src/dkg.rs (L452-460)
```rust
        verify_proof_of_knowledge(
            &session_id,
            &mut proof_domain_separator.clone(), // you want to have the same state
            threshold,
            p,
            old_participants.clone(),
            commitment_i,
            proof_i.as_ref(),
        )?;
```

**File:** src/ecdsa/robust_ecdsa/presign.rs (L226-232)
```rust
    if big_r
        .value()
        .ct_eq(&<Secp256K1Group as Group>::identity())
        .into()
    {
        return Err(ProtocolError::IdentityElement);
    }
```
