### Title
CKD Coordinator Accepts Unverified Participant Contributions, Allowing Any Malicious Participant to Corrupt the Confidential Derived Key Output - (File: `src/confidential_key_derivation/protocol.rs`)

### Summary
The `do_ckd_coordinator` function aggregates participant-supplied `(norm_big_y, norm_big_c)` pairs into the final CKD output without any proof of correctness. Because no commitment or zero-knowledge proof binds each participant's message to their actual private share, a single malicious participant can substitute arbitrary group elements, permanently corrupting the derived confidential key received by the application.

### Finding Description
The CKD protocol splits into two paths in `run_ckd_protocol`. Each non-coordinator participant calls `compute_signature_share`, which computes:

- `norm_big_y = λᵢ · yᵢ · G`
- `norm_big_c = λᵢ · (xᵢ · H(pk ‖ app_id) + yᵢ · app_pk)`

and sends the pair privately to the coordinator. [1](#0-0) 

The coordinator (`do_ckd_coordinator`) then aggregates every received pair with plain addition:

```rust
for (_, participant_output) in
    recv_from_others::<CKDOutput>(&chan, waitpoint, &participants, me).await?
{
    norm_big_y += participant_output.big_y();
    norm_big_c += participant_output.big_c();
}
``` [2](#0-1) 

There is no proof of knowledge, commitment binding, or any other check that the received `norm_big_c` was computed from the sender's actual private share `xᵢ` and the same ephemeral `yᵢ` used for `norm_big_y`. The sender identity returned by `recv_from_others` is discarded (`_`), and the content is accepted verbatim.

This is structurally identical to the external report's root cause: a value supplied by an external caller (`feeAmounts` / participant contribution) is received but its correctness is never validated before it is used in a critical calculation (repayment / key aggregation).

The `ckd` entry-point accepts no `threshold` parameter and provides no robustness mechanism, yet the protocol is presented without any documented restriction to the honest-but-curious model. [3](#0-2) 

### Impact Explanation
**High — Corruption of CKD output.** When a malicious participant substitutes an arbitrary `norm_big_c'` for the correct value, the coordinator computes:

```
C_final = Σ(honest contributions) + norm_big_c'
```

The invariant `C_final = msk · H(pk ‖ app_id) + Y · app_sk` is broken. The application's call to `unmask(app_sk)` returns a wrong group element, so the confidential derived key is permanently incorrect. Every honest party that relies on this output accepts an unusable cryptographic result. This matches the allowed impact: *"Corruption of … CKD outputs so honest parties accept … unusable cryptographic outputs."*

### Likelihood Explanation
The attack requires only that one participant in the CKD session is malicious. No privileged access, leaked keys, or cryptographic breaks are needed. The attacker simply serialises two arbitrary `ElementG1` values and sends them over the authenticated private channel to the coordinator. The coordinator has no way to distinguish this from a legitimate contribution.

### Recommendation
Require each participant to accompany their `(norm_big_y, norm_big_c)` with a Chaum-Pedersen discrete-log equality proof demonstrating that:

- `norm_big_y` and `norm_big_c - λᵢ · xᵢ · H(pk ‖ app_id)` share the same discrete log base `G` and `app_pk` respectively (i.e., both encode `λᵢ · yᵢ`).

The coordinator must verify every such proof before including the contribution in the aggregation. Additionally, document explicitly whether the protocol is designed only for the semi-honest model, and enforce that assumption at the API level if proofs are not added.

### Proof of Concept
1. Participant `P_malicious` is a legitimate member of the `participants` list passed to `ckd(...)`.
2. Instead of calling `compute_signature_share`, `P_malicious` constructs `norm_big_y = ElementG1::identity()` and `norm_big_c = ElementG1::generator()` (or any arbitrary point).
3. It sends `(norm_big_y, norm_big_c)` to the coordinator via `chan.send_private(waitpoint, coordinator, &(norm_big_y, norm_big_c))`.
4. The coordinator's loop at lines 50–55 adds these values unconditionally: `norm_big_c += G`.
5. The final `CKDOutput` satisfies `C ≠ msk · H(pk ‖ app_id) + Y · app_sk`.
6. The application calls `ckd_output.unmask(app_sk)` and receives a wrong element — the confidential derived key is corrupted for all honest parties.

### Citations

**File:** src/confidential_key_derivation/protocol.rs (L50-55)
```rust
    for (_, participant_output) in
        recv_from_others::<CKDOutput>(&chan, waitpoint, &participants, me).await?
    {
        norm_big_y += participant_output.big_y();
        norm_big_c += participant_output.big_c();
    }
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
