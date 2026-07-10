### Title
Malicious CKD Participant Sends Unverified `(big_y, big_c)` Shares to Corrupt Coordinator Output — (File: `src/confidential_key_derivation/protocol.rs`)

---

### Summary

The CKD coordinator in `do_ckd_coordinator` blindly accumulates `(big_y, big_c)` values received from participants with no proof of correctness. A single malicious participant can send arbitrary group elements, permanently corrupting the `CKDOutput` that the coordinator returns to the requester, causing the derived confidential key to be wrong for every honest party.

---

### Finding Description

In `do_ckd_coordinator`, the coordinator collects each participant's `CKDOutput` and adds the components together: [1](#0-0) 

```rust
for (_, participant_output) in
    recv_from_others::<CKDOutput>(&chan, waitpoint, &participants, me).await?
{
    norm_big_y += participant_output.big_y();
    norm_big_c += participant_output.big_c();
}
```

Each participant is supposed to compute and send:

- `norm_big_y = λ_i · y_i · G`
- `norm_big_c = λ_i · (x_i · H(pk ‖ app_id) + y_i · app_pk)`

where `x_i` is the participant's private signing share and `y_i` is a fresh random scalar. [2](#0-1) 

There is **no zero-knowledge proof, commitment, or any other verification** that the received `(big_y, big_c)` pair was honestly computed from the participant's actual key share `x_i`. The coordinator simply trusts whatever group elements arrive over the channel.

This is structurally identical to the OracleLess vulnerability: just as `OracleLess.fillOrder()` accepts an attacker-supplied `target` and `txData` without validation and executes them, `do_ckd_coordinator` accepts attacker-supplied `(big_y, big_c)` without validation and incorporates them into the final output.

The `CKDOutput` is later unmasked by the requester as: [3](#0-2) 

```rust
pub fn unmask(&self, secret_scalar: Scalar) -> Signature {
    self.big_c - self.big_y * secret_scalar
}
```

If any participant sends crafted `(big_y, big_c)`, the sum is poisoned and `unmask` yields a wrong group element — not `msk · H(pk ‖ app_id)`.

---

### Impact Explanation

**High — Corruption of CKD outputs so honest parties accept unusable cryptographic outputs.**

A single malicious participant can make the coordinator produce a `CKDOutput` whose `unmask` result is an arbitrary group element chosen (or randomized) by the attacker. Every honest party that relies on the coordinator's output will derive a wrong confidential key. Because the protocol has no round to detect or exclude the bad contributor, the attack succeeds on every invocation as long as the malicious participant is in the participant set.

---

### Likelihood Explanation

Any participant in the CKD protocol can mount this attack with no special privilege — they only need to deviate from the protocol by sending arbitrary `ElementG1` values instead of their honest share. The entry path is the normal `ckd()` public API: [4](#0-3) 

The only guard at initialization is membership and duplicate checks; there is no cryptographic binding of a participant's message to their key share.

---

### Recommendation

Require each participant to accompany their `(big_y, big_c)` with a zero-knowledge proof of correct formation — specifically, a proof that `big_c` was computed as `λ_i · (x_i · H(pk ‖ app_id) + y_i · app_pk)` for the same `x_i` committed to during DKG, and that `big_y = λ_i · y_i · G` for the same `y_i`. A standard Sigma protocol (e.g., a Chaum–Pedersen proof of discrete-log equality) over the pair `(big_y, big_c − λ_i · x_i · H(pk ‖ app_id))` relative to bases `(G, app_pk)` would suffice. The coordinator should verify each proof before accumulating the share.

---

### Proof of Concept

1. Honest participants `P1, P2` and malicious participant `P3` run `ckd()` with a shared `KeygenOutput` and `app_id`.
2. `P3` deviates: instead of calling `compute_signature_share`, it sends `CKDOutput::new(ElementG1::identity(), ElementG1::generator())` — arbitrary values.
3. The coordinator (say `P1`) executes the loop at lines 50–55 and accumulates `P3`'s poisoned values into `norm_big_y` and `norm_big_c`.
4. The coordinator returns `CKDOutput { big_y: honest_Y + identity, big_c: honest_C + G }`.
5. The requester calls `unmask(app_sk)` and obtains `honest_C + G − app_sk · honest_Y`, which is not `msk · H(pk ‖ app_id)`.
6. The derived confidential key is permanently wrong; no retry mechanism exists to detect or exclude `P3`. [5](#0-4)

### Citations

**File:** src/confidential_key_derivation/protocol.rs (L35-58)
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

**File:** src/confidential_key_derivation/mod.rs (L54-56)
```rust
    pub fn unmask(&self, secret_scalar: Scalar) -> Signature {
        self.big_c - self.big_y * secret_scalar
    }
```
