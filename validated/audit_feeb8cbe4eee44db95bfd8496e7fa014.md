### Title
Coordinator Aggregates Participant CKD Shares Without Cryptographic Validation, Allowing Any Participant to Corrupt the CKD Output — (File: `src/confidential_key_derivation/protocol.rs`)

---

### Summary

The CKD coordinator role is privileged: it is the sole party that receives and aggregates all participant shares and produces the final `CKDOutput`. However, `do_ckd_coordinator` accepts and unconditionally sums every participant's `(norm_big_y, norm_big_c)` pair with no cryptographic validation. Any single malicious participant can substitute arbitrary group elements, silently corrupting the coordinator's output. This is the direct analog of the external report's finding: a lower-privileged entity (participant) can directly influence a higher-privileged operation (coordinator output assembly) without any mediating validation layer.

---

### Finding Description

In `do_ckd_coordinator`, after computing its own share, the coordinator loops over all other participants' outputs and adds them unconditionally:

```rust
for (_, participant_output) in
    recv_from_others::<CKDOutput>(&chan, waitpoint, &participants, me).await?
{
    norm_big_y += participant_output.big_y();
    norm_big_c += participant_output.big_c();
}
let ckd_output = CKDOutput::new(norm_big_y, norm_big_c);
``` [1](#0-0) 

The expected honest computation for participant `i` is:

- `norm_big_y_i = λ_i · y_i · G`
- `norm_big_c_i = λ_i · (x_i · H(pk ‖ app_id) + y_i · app_pk)`

where `x_i` is the participant's private signing share and `y_i` is a fresh random scalar. [2](#0-1) 

No proof of correct formation is required or checked. The coordinator has no mechanism to distinguish a correctly formed share from an arbitrary pair of group elements. The `do_ckd_participant` path simply computes and sends the pair:

```rust
chan.send_private(waitpoint, coordinator, &(norm_big_y, norm_big_c))?;
``` [3](#0-2) 

There is no commitment, zero-knowledge proof, or consistency check on the received values before they are folded into the coordinator's running sum.

The privilege-separation gap is structural: the `ckd()` entry point validates participant membership and coordinator membership, but provides no mechanism for the coordinator to enforce that participants actually performed the correct computation. [4](#0-3) 

---

### Impact Explanation

The final `CKDOutput` is `(Σ norm_big_y_i, Σ norm_big_c_i)`. The intended confidential key is recovered by the application as:

```
confidential_key = big_c − app_sk · big_y
                 = Σ λ_i · x_i · H(pk ‖ app_id)
                 = msk · H(pk ‖ app_id)
```

If any single participant substitutes arbitrary elements `(Y', C')`, the sums become `(Σ norm_big_y_i + Y', Σ norm_big_c_i + C')`. The coordinator outputs this corrupted pair as the legitimate `CKDOutput`. Every honest party that relies on this output — including the coordinator itself — accepts a cryptographically invalid result. The derived confidential key is wrong and unusable, and there is no in-protocol signal that corruption occurred.

**Impact class**: High — Corruption of CKD outputs so honest parties accept unusable cryptographic outputs.

---

### Likelihood Explanation

The attack requires only that one participant in the CKD session behave maliciously. The participant role is the lowest-privilege role in the protocol; any participant can send an arbitrary byte string that deserializes as a valid `CKDOutput` (two group elements). No special position, no key material beyond membership, and no coordination with other parties is needed. The attack is silent: the coordinator returns `Ok(Some(ckd_output))` with no error. [5](#0-4) 

---

### Recommendation

Add a zero-knowledge proof of correct share formation to each participant's message. Concretely, each participant should prove in zero knowledge that:

1. `norm_big_y_i = λ_i · y_i · G` for some scalar `y_i` they know.
2. `norm_big_c_i = λ_i · (x_i · H(pk ‖ app_id) + y_i · app_pk)` where `x_i` is consistent with the participant's public verification share from the DKG output.

The coordinator must verify all proofs before aggregating. This mirrors the external report's recommendation: privileged operations (coordinator aggregation) must validate all inputs from lower-privileged callers (participants) before acting on them.

---

### Proof of Concept

1. Honest participants `P_1, …, P_{n-1}` run `do_ckd_participant` correctly, sending valid `(norm_big_y_i, norm_big_c_i)` to the coordinator.
2. Malicious participant `P_n` instead sends `(G1::generator(), G1::generator())` — two arbitrary non-zero group elements — as its `CKDOutput`.
3. The coordinator's loop at lines 50–55 adds these without complaint.
4. The coordinator returns `CKDOutput::new(norm_big_y + G, norm_big_c + G)`.
5. The application calls `ckd_output.unmask(app_sk)` and obtains `(norm_big_c + G) − app_sk · (norm_big_y + G)`, which equals `msk · H(pk ‖ app_id) + G − app_sk · G` — a value that is not the intended confidential key and is not zero, so the corruption is undetectable without an independent reference value.

### Citations

**File:** src/confidential_key_derivation/protocol.rs (L29-31)
```rust
    let waitpoint = chan.next_waitpoint();
    chan.send_private(waitpoint, coordinator, &(norm_big_y, norm_big_c))?;

```

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

**File:** src/confidential_key_derivation/protocol.rs (L159-181)
```rust
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
