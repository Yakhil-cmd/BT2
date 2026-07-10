### Title
Participant-Supplied `public_key` in `KeygenOutput` Is Not Cross-Validated Across CKD Participants, Enabling Corruption of CKD Output - (File: `src/confidential_key_derivation/protocol.rs`)

---

### Summary

The `ckd()` entry point accepts a caller-supplied `KeygenOutput` (containing `private_share` and `public_key`) from each participant independently. The `public_key` field is used inside `compute_signature_share` to compute the hash point `H(pk || app_id)`. Because no participant ever broadcasts or proves which `public_key` they used, a single malicious (or misconfigured) participant can silently substitute a different `public_key`, causing the coordinator to aggregate cryptographically inconsistent contributions and produce a `CKDOutput` that cannot be correctly unmasked.

---

### Finding Description

In `src/confidential_key_derivation/protocol.rs`, `compute_signature_share` computes:

```
hash_point = H(key_pair.public_key || app_id)
big_s      = hash_point * private_share          // x_i · H(pk_i || app_id)
big_c      = big_s + app_pk * y                  // x_i · H(pk_i || app_id) + y_i · A
``` [1](#0-0) 

Each participant's `key_pair.public_key` is taken directly from the caller-supplied argument with no cross-participant consistency check. The coordinator then blindly sums every participant's `(norm_big_y, norm_big_c)`:

```rust
for (_, participant_output) in recv_from_others(...) {
    norm_big_y += participant_output.big_y();
    norm_big_c += participant_output.big_c();
}
``` [2](#0-1) 

The `ckd()` initialization guard validates participant-list membership and coordinator presence, but performs **no check** that all participants share the same `public_key`: [3](#0-2) 

If participant `j` supplies `pk_j ≠ pk` (the agreed master public key), the aggregated ciphertext becomes:

```
C = (Σ_{i≠j} λ_i · x_i · H(pk || app_id))
  + λ_j · x_j · H(pk_j || app_id)
  + Σ λ_i · y_i · A
```

This is not equal to `msk · H(pk || app_id) + y · A`, so `unmask(app_sk) = C − app_sk · Y ≠ msk · H(pk || app_id)`. The derived confidential key is permanently wrong and the TEE application receives an unusable secret.

The `hash_app_id_with_pk` function that computes the hash point is defined in `src/confidential_key_derivation/mod.rs`: [4](#0-3) 

---

### Impact Explanation

A malicious participant (or an accidentally misconfigured one) causes the coordinator to output a `CKDOutput` whose `unmask` result is cryptographically incorrect. Every honest party that trusts the coordinator's output accepts a corrupted derived key. This maps directly to:

> **High: Corruption of CKD outputs so honest parties accept inconsistent public keys, participant sets, transcripts, or unusable cryptographic outputs.**

The corruption is silent — the coordinator returns `Ok(Some(ckd_output))` with no error, and the caller has no way to detect the substitution without an out-of-band check.

---

### Likelihood Explanation

The `KeygenOutput` struct is stored and re-supplied by each participant independently at signing time. There is no protocol-level mechanism that forces participants to commit to or prove the `public_key` they used. A single malicious participant among `n` is sufficient to corrupt every CKD invocation for a given `app_id`. The attack requires only that the participant call `ckd()` with a modified `KeygenOutput`; no cryptographic capability is needed.

---

### Recommendation

Before executing the CKD protocol, enforce that all participants agree on the same `public_key`. One approach:

1. **Broadcast-and-compare**: Have each participant broadcast a commitment (e.g., a hash) to their `key_pair.public_key` at the start of the protocol. The coordinator verifies all commitments match before aggregating shares.
2. **Coordinator-supplied canonical key**: Pass the agreed `public_key` as a separate, explicit parameter to `ckd()` (independent of each participant's `KeygenOutput`), and use that canonical key in `compute_signature_share` instead of `key_pair.public_key`. Each participant's `key_pair.public_key` can then be checked against it at initialization.

---

### Proof of Concept

1. Run DKG for 3 participants, obtaining `KeygenOutput { private_share: x_i, public_key: pk }` for each.
2. Participant 1 (malicious) constructs `bad_key_pair = KeygenOutput { private_share: x_1, public_key: pk' }` where `pk' ≠ pk`.
3. All participants call `ckd(participants, coordinator, me, key_pair, app_id, app_pk, rng)` — participant 1 passes `bad_key_pair`.
4. The coordinator aggregates and returns `CKDOutput { big_y, big_c }`.
5. The TEE calls `ckd_output.unmask(app_sk)` and receives a value that does not equal `msk · H(pk || app_id)`.
6. The expected confidential key `hash_app_id_with_pk(&pk, &app_id) * msk` is never recoverable from this output. [5](#0-4)

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

**File:** src/confidential_key_derivation/protocol.rs (L74-101)
```rust
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

**File:** src/confidential_key_derivation/mod.rs (L67-71)
```rust
pub fn hash_app_id_with_pk(pk: &VerifyingKey, app_id: &[u8]) -> ElementG1 {
    let compressed_pk = pk.to_element().to_compressed();
    let input = [compressed_pk.as_slice(), app_id].concat();
    ciphersuite::hash_to_curve(&input)
}
```
