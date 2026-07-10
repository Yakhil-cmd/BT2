### Title
Malicious CKD Participant Can Silently Corrupt the Derived Key Output Without Detection — (File: `src/confidential_key_derivation/protocol.rs`)

### Summary

The CKD coordinator aggregates per-participant shares `(big_y, big_c)` with no cryptographic verification of their correctness. Any single malicious participant can send arbitrary group elements, causing the coordinator to produce a silently corrupted `CKDOutput`. Unlike the DKG protocol, which enforces proof-of-knowledge and commitment-hash checks on every received value, the CKD protocol has no equivalent safeguards, so corruption is undetectable by honest parties.

### Finding Description

In `do_ckd_coordinator` the coordinator blindly sums every received share:

```rust
// src/confidential_key_derivation/protocol.rs  lines 50-55
for (_, participant_output) in
    recv_from_others::<CKDOutput>(&chan, waitpoint, &participants, me).await?
{
    norm_big_y += participant_output.big_y();
    norm_big_c += participant_output.big_c();
}
``` [1](#0-0) 

The protocol specification requires each participant `i` to send:

```
norm_big_y_i = λ_i · y_i · G
norm_big_c_i = λ_i · (x_i · H(pk ‖ app_id) + y_i · app_pk)
```

computed in `compute_signature_share`: [2](#0-1) 

Nothing in the protocol verifies that the received `(big_y, big_c)` pair is consistent with the sender's public key share or with the correct Lagrange coefficient. A malicious participant can transmit any two arbitrary `G1` points. The coordinator adds them to the running sum and returns the corrupted `CKDOutput` as if it were valid.

**Contrast with DKG.** The DKG protocol enforces three independent checks on every received value:

- `verify_proof_of_knowledge` — Schnorr PoK that the sender knows the secret behind their commitment. [3](#0-2) 
- `verify_commitment_hash` — hash-binding to prevent adaptive commitment changes. [4](#0-3) 
- `validate_received_share` — algebraic consistency of the secret share against the public commitment. [5](#0-4) 

None of these mechanisms exist in the CKD protocol. The participant path simply sends its share and returns `None`: [6](#0-5) 

**Attacker-controlled entry path.** The attacker is a valid participant in the `ckd()` call — no privileged role is required. The `ckd` entry point accepts any participant from the declared list: [7](#0-6) 

The attacker's protocol instance reaches `do_ckd_participant`, computes the correct share, then substitutes arbitrary `(big_y, big_c)` values before calling `chan.send_private`. The coordinator has no way to distinguish this from a legitimate share.

### Impact Explanation

The coordinator's `CKDOutput` is the only output of the protocol. When the application calls `unmask(app_sk)`:

```rust
pub fn unmask(&self, secret_scalar: Scalar) -> Signature {
    self.big_c - self.big_y * secret_scalar
}
``` [8](#0-7) 

it computes `big_c − app_sk · big_y`. With a corrupted `big_y` or `big_c`, the result is an arbitrary group element that does not equal `msk · H(pk ‖ app_id)`. The derived confidential key is silently wrong — no error is raised, no abort occurs, and the honest coordinator has no indication the output is invalid.

This matches the **High** allowed impact: *Corruption of CKD outputs so honest parties accept unusable cryptographic outputs.*

### Likelihood Explanation

The attacker needs only to be a listed participant in a CKD session — a role reachable without any privileged access. The attack requires sending two malformed group elements in a single protocol message. It is silent, requires no timing precision, and succeeds deterministically. Any one of the N participants can trigger it unilaterally.

### Recommendation

Add a zero-knowledge proof of correct share formation alongside each `(big_y, big_c)` message. Concretely, each participant should prove in zero knowledge that:

1. `big_y = λ_i · y_i · G` for some `y_i` they know (a Schnorr PoK on `big_y / λ_i`).
2. `big_c = λ_i · (x_i · H(pk ‖ app_id) + y_i · app_pk)` is consistent with their public key share `X_i = x_i · G2` (a Chaum–Pedersen DLEQ proof relating `big_y / λ_i` and `(big_c / λ_i − x_i · H(pk ‖ app_id)) / app_pk`).

Alternatively, adopt a commit-then-reveal structure analogous to DKG round 2 (`commitment_hash` broadcast before the actual values), so participants cannot adaptively choose their shares after seeing others'.

### Proof of Concept

1. Start a CKD session with participants `[P1, P2, P3]`, coordinator `P1`.
2. `P2` runs `compute_signature_share` normally but, before calling `chan.send_private`, replaces the result with `(G, G)` (the generator point for both fields).
3. `P1` (coordinator) receives `(G, G)` from `P2`, adds it to its own correct share and `P3`'s correct share.
4. The coordinator returns a `CKDOutput` where `big_y` and `big_c` are each off by one generator point.
5. `unmask(app_sk)` returns `big_c − app_sk · big_y ≠ msk · H(pk ‖ app_id)`.
6. No error is raised anywhere in the library; the corrupted key is silently accepted.

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

**File:** src/confidential_key_derivation/protocol.rs (L50-56)
```rust
    for (_, participant_output) in
        recv_from_others::<CKDOutput>(&chan, waitpoint, &participants, me).await?
    {
        norm_big_y += participant_output.big_y();
        norm_big_c += participant_output.big_c();
    }
    let ckd_output = CKDOutput::new(norm_big_y, norm_big_c);
```

**File:** src/confidential_key_derivation/protocol.rs (L66-117)
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

    let comms = Comms::new();
    let chan = comms.shared_channel();

    let fut = run_ckd_protocol(
        chan,
        coordinator,
        me,
        participants,
        key_pair,
        app_id.into(),
        app_pk,
        rng,
    );
    Ok(make_protocol(comms, fut))
}
```

**File:** src/confidential_key_derivation/protocol.rs (L148-182)
```rust
fn compute_signature_share(
    participants: &ParticipantList,
    me: Participant,
    key_pair: &KeygenOutput,
    app_id: &AppId,
    app_pk: PublicKey,
    rng: &mut impl CryptoRngCore,
) -> Result<(ElementG1, ElementG1), ProtocolError> {
    // Ensures the value is zeroized on drop
    let private_share = Zeroizing::new(key_pair.private_share);

    // y <- ZZq* , Y <- y * G
    let y = Scalar::random(rng);

    // Ensures the value is zeroized on drop
    let y = Zeroizing::new(super::scalar_wrapper::ScalarWrapper(y));

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

**File:** src/dkg.rs (L222-236)
```rust
fn verify_commitment_hash<C: Ciphersuite>(
    session_id: &HashOutput,
    participant: Participant,
    domain_separator: &mut DomainSeparator,
    commitment: &VerifiableSecretSharingCommitment<C>,
    all_hash_commitments: &ParticipantMap<'_, HashOutput>,
) -> Result<(), ProtocolError> {
    let actual_commitment_hash = all_hash_commitments.index(participant)?;
    let commitment_hash =
        domain_separate_hash(domain_separator, &(&participant, &commitment, &session_id))?;
    if *actual_commitment_hash != commitment_hash {
        return Err(ProtocolError::InvalidCommitmentHash);
    }
    Ok(())
}
```

**File:** src/dkg.rs (L259-286)
```rust
fn validate_received_share<C: Ciphersuite>(
    me: Participant,
    from: Participant,
    signing_share_from: &SigningShare<C>,
    commitment: &VerifiableSecretSharingCommitment<C>,
) -> Result<(), ProtocolError> {
    let id = me.to_identifier::<C>()?;

    // The verification is exactly the same as the regular SecretShare verification;
    // however the required components are in different places.
    // Build a temporary SecretShare so what we can call verify().
    let secret_share = SecretShare::new(id, *signing_share_from, commitment.clone());

    // Verify the share. We don't need the result.
    // Identify the culprit if an InvalidSecretShare error is returned.
    secret_share.verify().map_err(|e| {
        if let Error::InvalidSecretShare { .. } = e {
            ProtocolError::InvalidSecretShare(from)
        } else {
            ProtocolError::AssertionFailed(format!(
                "could not
            extract the verification key matching the secret
            share sent by {from:?}"
            ))
        }
    })?;
    Ok(())
}
```

**File:** src/confidential_key_derivation/mod.rs (L54-56)
```rust
    pub fn unmask(&self, secret_scalar: Scalar) -> Signature {
        self.big_c - self.big_y * secret_scalar
    }
```
