### Title
Missing Validation of `app_pk` Identity Element Allows Coordinator to Extract Confidential Derived Key — (File: `src/confidential_key_derivation/protocol.rs`)

---

### Summary

The `ckd()` function in the CKD protocol accepts `app_pk` (the client's ElGamal public key) without validating that it is a non-identity group element. If `app_pk` is the G1 identity, the ElGamal encryption that is supposed to hide the BLS signature from the signing parties is completely broken, and the coordinator directly learns the confidential derived key from the protocol output.

---

### Finding Description

The CKD protocol's security guarantee is that the signing parties (including the coordinator) learn only an ElGamal-encrypted form of `msk · H(pk ‖ app_id)`. The client decrypts it using their secret key `app_sk`. This guarantee depends entirely on `app_pk` being a valid, non-identity group element.

In `compute_signature_share`, each participant computes:

```rust
let big_c = big_s + app_pk * y.0;
```

where `big_s = hash_point * private_share` is the participant's BLS signature share. [1](#0-0) 

If `app_pk` is `G1Projective::identity()` (the zero element), then `app_pk * y.0 = identity`, so:

```
big_c = big_s + identity = big_s
```

Each participant's `norm_big_c = lambda_i * big_s_i` is sent to the coordinator. The coordinator sums them:

```
big_c_total = Σ lambda_i · big_s_i = msk · H(pk ‖ app_id)
```

This is the confidential derived key itself. The coordinator reads it directly from `CKDOutput.big_c` without needing `app_sk`. [2](#0-1) 

The `ckd()` entry point performs several input validations (participant count, duplicates, self-membership, coordinator membership) but performs **no validation on `app_pk`**: [3](#0-2) 

The `CKDOutput.unmask` function is designed for the client to recover the key using `app_sk`. When `app_pk = identity`, the coordinator already holds the plaintext key in `big_c` and does not need `unmask` at all: [4](#0-3) 

---

### Impact Explanation

This is a **Critical** impact: **Extraction, reconstruction, or disclosure of confidential derived secrets**.

The entire confidentiality property of the CKD protocol collapses. The coordinator, who is explicitly not supposed to learn `msk · H(pk ‖ app_id)`, obtains it directly from the protocol output. The client's ElGamal secret key `app_sk` provides no protection.

---

### Likelihood Explanation

A malicious coordinator controls the `app_pk` value they pass to their own `ckd()` invocation. In typical deployments, the coordinator also relays protocol parameters (including `app_pk`) to other participants. By distributing `app_pk = G1::identity()` to all participants, the coordinator causes every participant to strip the ElGamal blinding from their share before sending it. The coordinator then aggregates the unblinded shares and reads the confidential key directly.

This requires only that the coordinator be malicious — a threat explicitly within scope per `RESEARCHER.md` ("Malicious peer/integrator/oracle only where that role is reachable without privileged assumptions"). [5](#0-4) 

---

### Recommendation

Add an identity-element check in `ckd()` before the protocol runs:

```rust
use elliptic_curve::Group;

if app_pk == ElementG1::identity() {
    return Err(InitializationError::BadParameters(
        "app_pk must not be the identity element".to_string(),
    ));
}
```

This mirrors the fix in the external report: just as `require(rewardTokensList[_reward], "Invalid reward")` guards against unregistered tokens, a guard on `app_pk` prevents the encryption invariant from being silently bypassed.

---

### Proof of Concept

**Setup**: 3-participant CKD session. Malicious coordinator `P_0` controls `app_pk` distribution.

1. `P_0` calls `ckd(..., app_pk = G1Projective::identity(), ...)` for itself.
2. `P_0` distributes `app_pk = G1Projective::identity()` to `P_1` and `P_2` (instead of the real client public key).
3. Each participant `P_i` computes:
   - `big_s_i = H(pk ‖ app_id) * x_i`
   - `big_c_i = big_s_i + identity * y_i = big_s_i`
   - Sends `(lambda_i * y_i * G, lambda_i * big_s_i)` to coordinator.
4. Coordinator sums: `big_c = Σ lambda_i * big_s_i = msk * H(pk ‖ app_id)`.
5. Coordinator reads `ckd_output.big_c()` — this is the confidential derived key, obtained without the client's `app_sk`.

### Citations

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

**File:** src/confidential_key_derivation/protocol.rs (L170-174)
```rust
    // S <- x . H(app_id)
    let big_s = hash_point * private_share.to_scalar();

    // C <- S + y . A
    let big_c = big_s + app_pk * y.0;
```

**File:** src/confidential_key_derivation/mod.rs (L54-56)
```rust
    pub fn unmask(&self, secret_scalar: Scalar) -> Signature {
        self.big_c - self.big_y * secret_scalar
    }
```

**File:** RESEARCHER.md (L36-43)
```markdown
## Attacker Profiles You Must Emulate

- External attacker with no privileged keys (default).
- Malicious normal user abusing valid product/protocol flows.
- Malicious API/RPC/web client submitting crafted inputs at scale.
- Malicious peer/integrator/oracle only where that role is reachable without
  privileged assumptions.

```
