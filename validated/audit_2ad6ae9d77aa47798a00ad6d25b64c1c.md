### Title
Malicious CKD Participant Can Corrupt Coordinator's Output by Sending Arbitrary Share Values — (File: `src/confidential_key_derivation/protocol.rs`)

### Summary

In the CKD protocol, the coordinator receives `(norm_big_y, norm_big_c)` from every participant and accumulates them with plain addition. There is no zero-knowledge proof, commitment, or any other check that a participant computed those values honestly. A single malicious participant can send arbitrary group elements, silently corrupting the final `CKDOutput` that the coordinator returns to the application.

### Finding Description

`do_ckd_coordinator` aggregates participant shares as follows: [1](#0-0) 

```rust
for (_, participant_output) in
    recv_from_others::<CKDOutput>(&chan, waitpoint, &participants, me).await?
{
    norm_big_y += participant_output.big_y();
    norm_big_c += participant_output.big_c();
}
```

Each honest participant is supposed to compute: [2](#0-1) 

- `norm_big_y = λᵢ · yᵢ · G`
- `norm_big_c = λᵢ · (xᵢ · H(pk ‖ app_id) + yᵢ · app_pk)`

so that the coordinator's aggregate satisfies `C − app_sk · Y = msk · H(pk ‖ app_id)`.

A malicious participant's `do_ckd_participant` path simply calls `chan.send_private` with whatever bytes it chooses: [3](#0-2) 

There is no proof-of-correct-computation attached to the message, and the coordinator performs no verification before adding the received elements to the running sum. The `CKDOutput` is constructed directly from the (potentially poisoned) accumulator: [4](#0-3) 

### Impact Explanation

The final `CKDOutput(Y′, C′)` will be an arbitrary pair of group elements chosen by the attacker. The `unmask(app_sk)` operation — which computes `C′ − app_sk · Y′` — will return a value that is not `msk · H(pk ‖ app_id)`. Every downstream consumer (TEE, application) that relies on this output will silently receive a wrong confidential key. The corruption is undetectable by the coordinator because no honest-computation proof is ever exchanged.

This matches the allowed impact: **High — Corruption of CKD outputs so honest parties accept unusable cryptographic outputs.**

### Likelihood Explanation

The attacker only needs to be one enrolled participant in a single CKD invocation. No threshold of colluders is required; one malicious party is sufficient. The attack requires no special cryptographic capability — the participant simply replaces its outgoing message with arbitrary curve points. The entry path is the standard `ckd()` public API: [5](#0-4) 

### Recommendation

Attach a Schnorr-style proof of correct computation to each participant's message. Concretely, each participant must prove in zero knowledge that:

1. `norm_big_y = λᵢ · yᵢ · G` for a committed `yᵢ`, and
2. `norm_big_c = λᵢ · xᵢ · H(pk ‖ app_id) + λᵢ · yᵢ · app_pk` for the **same** `yᵢ` and the participant's public key share `λᵢ · xᵢ · G` (derivable from the DKG output).

The coordinator must verify every such proof before adding the share to the accumulator, and abort if any proof fails.

### Proof of Concept

1. Honest participants run `ckd()` with a valid `KeygenOutput` and `app_pk`.
2. Malicious participant `Pₘ` overrides its outgoing message: instead of the correctly computed `(norm_big_y, norm_big_c)`, it sends `(G, G)` (the generator point for both fields).
3. The coordinator's loop at lines 50–55 adds `G` to both accumulators unconditionally.
4. The resulting `CKDOutput` satisfies `C′ = C_honest + G` and `Y′ = Y_honest + G`.
5. `unmask(app_sk)` computes `C′ − app_sk · Y′ = msk · H(pk ‖ app_id) + G − app_sk · G`, which is not the expected confidential key.
6. The TEE or application receives a wrong key with no indication that anything went wrong, permanently breaking any operation that depends on the derived secret.

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

**File:** src/confidential_key_derivation/protocol.rs (L56-57)
```rust
    let ckd_output = CKDOutput::new(norm_big_y, norm_big_c);
    Ok(Some(ckd_output))
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

**File:** src/confidential_key_derivation/protocol.rs (L148-181)
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
```
