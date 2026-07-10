### Title
Malicious CKD Participant Can Corrupt Coordinator Output Without Detection — (`File: src/confidential_key_derivation/protocol.rs`)

### Summary
The CKD coordinator blindly accumulates `(norm_big_y, norm_big_c)` shares from every participant with no proof of correct computation. Any single malicious participant can substitute arbitrary group elements, silently corrupting the final `CKDOutput` that the coordinator accepts as valid. By contrast, the DKG protocol validates every received share against a commitment and a proof of knowledge before accepting it.

### Finding Description
In `do_ckd_coordinator` the coordinator receives each participant's contribution and immediately adds it to the running sum:

```rust
for (_, participant_output) in
    recv_from_others::<CKDOutput>(&chan, waitpoint, &participants, me).await?
{
    norm_big_y += participant_output.big_y();
    norm_big_c += participant_output.big_c();
}
``` [1](#0-0) 

There is no check that `big_y` equals `y_i * G` for any committed nonce, no check that `big_c` was formed as `hash_point * x_i + y_i * app_pk`, and no zero-knowledge proof binding the contribution to the participant's actual key share. A participant can send any pair of `ElementG1` values.

Compare this with the DKG protocol, which validates every received share in three independent ways before accepting it:

1. `verify_proof_of_knowledge` — checks a Schnorr proof that the sender knows the secret behind their commitment. [2](#0-1) 
2. `verify_commitment_hash` — checks that the commitment matches the hash broadcast in round 1. [3](#0-2) 
3. `validate_received_share` — verifies the secret share against the polynomial commitment. [4](#0-3) 

The CKD protocol performs none of these checks. The `ckd()` entry point validates the participant list and coordinator membership, but applies zero cryptographic validation to the shares that actually determine the output. [5](#0-4) 

### Impact Explanation
The CKD output `(Y, C)` is computed as:

```
Y = Σ λ_i · y_i · G
C = Σ λ_i · (x_i · H(pk, app_id) + y_i · app_pk)
  = H(pk, app_id) · msk  +  Y · app_sk
```

The application TEE unmasks with `C − app_sk · Y = H(pk, app_id) · msk`, the confidential derived key. If any participant replaces their `(norm_big_y, norm_big_c)` with arbitrary group elements `(Y', C')`, the coordinator computes a corrupted sum and returns a `CKDOutput` that does not correspond to any valid derivation of the master secret key. The coordinator has no way to detect the manipulation or identify the culprit. Every honest party accepts this corrupted output as the protocol result.

This matches the allowed impact: **High — Corruption of CKD outputs so honest parties accept unusable cryptographic outputs.**

### Likelihood Explanation
The attack requires only one malicious participant among the `N` parties who run `ckd()`. The participant's deviation is a single message substitution in a one-round protocol with no accountability mechanism. There is no transcript, commitment, or proof that would expose the cheating after the fact. Any participant who wishes to deny a TEE its correct confidential key, or to force a retry, can do so deterministically and undetectably.

### Recommendation
Add a zero-knowledge proof of correct share formation to each participant's message. Concretely, each participant should prove in zero knowledge that:
- `big_y = y_i · G` for the same `y_i` used in `big_c`, and
- `big_c = x_i · H(pk, app_id) + y_i · app_pk` for their committed key share `x_i`.

A standard ElGamal correctness proof (a Chaum–Pedersen DLEQ proof) suffices for the `y_i` consistency, and a separate proof of correct BLS share evaluation covers the `x_i` term. The coordinator should verify all proofs before accumulating any contribution, mirroring the pattern already established in `do_keyshare` for DKG.

### Proof of Concept
```rust
// Malicious participant overrides do_ckd_participant to send garbage shares.
// The coordinator has no way to detect this.
fn do_ckd_participant_malicious(
    mut chan: SharedChannel,
    coordinator: Participant,
) -> Result<CKDOutputOption, ProtocolError> {
    let waitpoint = chan.next_waitpoint();
    // Send arbitrary group elements instead of the correct share
    let fake_big_y = ElementG1::generator(); // arbitrary non-zero point
    let fake_big_c = ElementG1::generator(); // arbitrary non-zero point
    chan.send_private(waitpoint, coordinator, &(fake_big_y, fake_big_c))?;
    Ok(None)
}

// The coordinator accumulates the fake values without any check:
//   norm_big_y += fake_big_y;   // corrupts Y
//   norm_big_c += fake_big_c;   // corrupts C
// The returned CKDOutput is silently wrong; unmask() yields a random point,
// not H(pk, app_id) · msk.
``` [6](#0-5)

### Citations

**File:** src/confidential_key_derivation/protocol.rs (L35-57)
```rust
async fn do_ckd_coordinator(
    mut chan: SharedChannel,
    participants: ParticipantList,
    me: Participant,
    key_pair: &KeygenOutput,
    app_id: &AppId,
    app_pk: PublicKey,
    rng: &mut impl CryptoRngCore,
) -> Result<CKDOutputOption, ProtocolError> {
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

**File:** src/confidential_key_derivation/protocol.rs (L76-101)
```rust
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

**File:** src/dkg.rs (L463-469)
```rust
        verify_commitment_hash(
            &session_id,
            p,
            &mut commit_domain_separator.clone(), // you want to have the same state
            commitment_i,
            &all_hash_commitments,
        )?;
```

**File:** src/dkg.rs (L520-522)
```rust
        let full_commitment_from = all_full_commitments.index(from)?;
        // Step 5.2
        validate_received_share::<C>(me, from, &signing_share_from, full_commitment_from)?;
```
