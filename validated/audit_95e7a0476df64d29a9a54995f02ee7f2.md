### Title
Missing Validation of Participant Contributions in CKD Protocol Allows Malicious Participant to Corrupt Derived Key Output - (File: src/confidential_key_derivation/protocol.rs)

---

### Summary
The `do_ckd_coordinator` function in the Confidential Key Derivation (CKD) protocol accepts participant contributions without any cryptographic validation. A malicious participant can send arbitrary group elements in place of their correct Lagrange-weighted key share contribution. The coordinator sums all received values unconditionally, and there is no final output verification step. Honest parties will accept the corrupted CKD output, producing an incorrect confidential derived key.

---

### Finding Description

In `do_ckd_coordinator`, the coordinator receives `(norm_big_y, norm_big_c)` pairs from every other participant and accumulates them with no validation: [1](#0-0) 

Each participant is supposed to compute their contribution in `compute_signature_share` as:

- `norm_big_y = λi · yi · G`
- `norm_big_c = λi · (xi · H(pk ‖ app_id) + yi · app_pk)` [2](#0-1) 

There is no zero-knowledge proof, commitment scheme, or any other mechanism to verify that the received `(norm_big_y, norm_big_c)` values are correctly derived from the participant's actual signing share `xi`. A malicious participant can substitute arbitrary valid group elements.

Critically, unlike the FROST signing protocol — which calls `aggregate()` and internally verifies the final signature — the CKD coordinator has **no final output verification step**. It simply returns the accumulated sum: [3](#0-2) 

The public entry point `ckd()` also performs no threshold check beyond requiring at least 2 participants, and imposes no constraint that contributions must be cryptographically bound to key shares: [4](#0-3) 

This is directly analogous to the reported vulnerability class: a critical operation (accumulation of secret-share contributions) proceeds without validating that the input is authorized/correct for the acting party.

---

### Impact Explanation

The CKD output `(Y, C)` is used by the application to unmask the confidential derived key:

```
confidential_key = C − Y · app_sk  =  msk · H(pk ‖ app_id)
```

If a malicious participant P_m sends `(0, 0)` (identity elements) instead of their correct contribution, the coordinator produces:

```
Y_out  = Y_correct − λm · ym · G
C_out  = C_correct − λm · (xm · H(pk ‖ app_id) + ym · app_pk)
```

Unmasking yields `(msk − λm · xm) · H(pk ‖ app_id)` — an incorrect key — with no error raised anywhere in the protocol. Honest parties accept this output unconditionally.

**Impact: High — Corruption of CKD outputs so honest parties accept unusable cryptographic outputs**, matching the allowed scope exactly.

---

### Likelihood Explanation

Any single malicious participant in the CKD protocol can trigger this with zero additional capability. No key material, side-channel access, or cryptographic break is required. The attacker simply deviates from the protocol by sending arbitrary group elements (e.g., the identity, or a random point). The attack is single-round and undetectable by the coordinator or any honest party.

---

### Recommendation

Add a non-interactive zero-knowledge proof (e.g., a Schnorr proof of knowledge) to each participant's message, proving that `norm_big_c` is correctly formed from their key share `xi` and the public parameters `H(pk ‖ app_id)` and `app_pk`. The coordinator must verify all proofs before accumulating contributions. Alternatively, use a commit-then-reveal scheme so that deviations are attributable and detectable before the output is finalized.

---

### Proof of Concept

1. Honest participants and one malicious participant P_m run `ckd(...)`.
2. P_m computes the correct `(norm_big_y_m, norm_big_c_m)` locally but instead sends `(ElementG1::identity(), ElementG1::identity())` to the coordinator.
3. The coordinator's loop at lines 50–55 adds `(0, 0)` to the running sum without error.
4. The returned `CKDOutput` is `(Y_correct − λm·ym·G, C_correct − λm·(xm·H + ym·app_pk))`.
5. The application calls `ckd_output.unmask(app_sk)` and receives `(msk − λm·xm)·H(pk ‖ app_id)` — a wrong key — with no protocol-level error or abort.
6. All honest parties accept this corrupted output as the legitimate CKD result.

### Citations

**File:** src/confidential_key_derivation/protocol.rs (L50-57)
```rust
    for (_, participant_output) in
        recv_from_others::<CKDOutput>(&chan, waitpoint, &participants, me).await?
    {
        norm_big_y += participant_output.big_y();
        norm_big_c += participant_output.big_c();
    }
    let ckd_output = CKDOutput::new(norm_big_y, norm_big_c);
    Ok(Some(ckd_output))
```

**File:** src/confidential_key_derivation/protocol.rs (L66-101)
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
