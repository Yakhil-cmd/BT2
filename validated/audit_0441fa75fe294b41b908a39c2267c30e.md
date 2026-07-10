### Title
Missing Cryptographic Verification of Participant Contributions in CKD Coordinator Allows Malicious Participant to Corrupt Confidential Key Output - (File: `src/confidential_key_derivation/protocol.rs`)

### Summary
The `do_ckd_coordinator` function in the CKD protocol unconditionally accumulates `(big_y, big_c)` values received from participants without any cryptographic verification that those values were computed correctly from the participant's actual private share. A single malicious participant can send arbitrary group elements, causing the coordinator to output a corrupted `CKDOutput` that, when unmasked by the TEE application, yields a wrong confidential key.

### Finding Description

In `do_ckd_coordinator` (`src/confidential_key_derivation/protocol.rs`, lines 35–58), the coordinator receives each participant's `(norm_big_y, norm_big_c)` pair and adds them directly to the running totals:

```rust
for (_, participant_output) in
    recv_from_others::<CKDOutput>(&chan, waitpoint, &participants, me).await?
{
    norm_big_y += participant_output.big_y();
    norm_big_c += participant_output.big_c();
}
``` [1](#0-0) 

No proof of correctness accompanies these values. The `compute_signature_share` function that honest participants use produces:

- `big_y = lambda_i * y_i * G` (random nonce scaled by Lagrange coefficient)
- `big_c = lambda_i * (x_i * H(pk || app_id) + y_i * app_pk)` (private share contribution) [2](#0-1) 

There is no zero-knowledge proof, commitment check, or any other mechanism that binds the received `(big_y, big_c)` to the participant's actual private share `x_i`. The `KeygenOutput` passed to each participant contains only the aggregate `public_key`, not individual share commitments, so the coordinator has no reference material to verify against. [3](#0-2) 

The `ckd` entry point performs only structural checks (duplicate participants, self-presence, coordinator-presence) and accepts no threshold parameter — meaning the protocol implicitly requires **all** participants to be honest. [4](#0-3) 

### Impact Explanation

A malicious participant `P_m` sends `(big_y', big_c')` of their choosing. The coordinator computes:

```
total_big_y = Σ_{i≠m} λ_i·y_i·G  +  big_y'
total_big_c = Σ_{i≠m} λ_i·(x_i·H(pk‖app_id) + y_i·app_pk)  +  big_c'
```

When the TEE unmasks with `app_sk`:

```
total_big_c − app_sk·total_big_y
  = (msk − λ_m·x_m)·H(pk‖app_id)  +  (big_c' − app_sk·big_y')
```

Setting `big_y' = identity` and `big_c' = identity` (zero contribution) yields `(msk − λ_m·x_m)·H(pk‖app_id)` — a wrong key with no error signal. Setting `big_c'` to an arbitrary non-zero element injects an uncontrolled but attacker-chosen additive offset into the derived secret. In either case the TEE silently accepts and uses a corrupted confidential key. There is no final verification step analogous to the signature check present in the OT-based ECDSA signing path. [5](#0-4) 

This matches the allowed impact: **High — Corruption of CKD outputs so honest parties accept unusable or incorrect cryptographic outputs.**

### Likelihood Explanation

**Medium.** Any single participant in the CKD session can mount this attack. The protocol is designed for decentralized MPC networks where participants may be adversarial. No special capability beyond participation in the protocol is required — the attacker simply sends malformed group elements over the normal message channel. The attack is silent (no error is raised) and requires no coordination with other parties.

### Recommendation

Require each participant to accompany their `(big_y, big_c)` contribution with a non-interactive zero-knowledge proof of correct computation — specifically, a proof of knowledge of `y_i` such that `big_y = lambda_i * y_i * G` and `big_c = lambda_i * (x_i * H(pk‖app_id) + y_i * app_pk)`, where `x_i` is bound to the public share commitment from the DKG output. Alternatively, propagate per-participant share commitments from `KeygenOutput` into the CKD protocol so the coordinator can verify `big_c - big_y * (app_pk / G) == lambda_i * x_i * H(pk‖app_id)` in the exponent.

### Proof of Concept

1. Run a 3-participant CKD session with participants `[P1, P2, P3]` and coordinator `P1`.
2. Configure `P2` to send `(ElementG1::identity(), ElementG1::identity())` instead of its correct share.
3. Observe that the coordinator outputs a `CKDOutput` without error.
4. Have the TEE call `ckd_output.unmask(app_sk)` and observe the result equals `(msk − λ_2·x_2)·H(pk‖app_id)` rather than `msk·H(pk‖app_id)`, confirming silent corruption of the derived confidential key. [6](#0-5)

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

**File:** src/confidential_key_derivation/protocol.rs (L66-116)
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

**File:** src/ecdsa/ot_based_ecdsa/sign.rs (L128-133)
```rust
    // Spec 1.8
    if !sig.verify(&public_key, &msg_hash) {
        return Err(ProtocolError::AssertionFailed(
            "signature failed to verify".to_string(),
        ));
    }
```
