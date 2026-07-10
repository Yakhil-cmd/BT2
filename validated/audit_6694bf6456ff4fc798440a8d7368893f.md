### Title
Malicious Participant Can Corrupt CKD Output by Supplying a Mismatched `public_key` in `KeygenOutput` — (File: src/confidential_key_derivation/protocol.rs)

---

### Summary

The CKD protocol computes `H(pk || app_id)` using `key_pair.public_key` supplied locally by each participant, but never validates that all participants are using the same master public key. A malicious participant can pass a `KeygenOutput` whose `public_key` differs from the one established during DKG, silently corrupting the aggregated `CKDOutput` accepted by the coordinator and the client.

---

### Finding Description

In `compute_signature_share` (protocol.rs, line 168), the hash point is computed as:

```rust
let hash_point = hash_app_id_with_pk(&key_pair.public_key, app_id);
``` [1](#0-0) 

`hash_app_id_with_pk` concatenates the compressed master BLS public key with `app_id` and hashes to a curve point:

```rust
pub fn hash_app_id_with_pk(pk: &VerifyingKey, app_id: &[u8]) -> ElementG1 {
    let compressed_pk = pk.to_element().to_compressed();
    let input = [compressed_pk.as_slice(), app_id].concat();
    ciphersuite::hash_to_curve(&input)
}
``` [2](#0-1) 

Each participant's contribution to `big_c` is:

```
big_c_i = lambda_i * (x_i * H(pk_i || app_id) + y_i * app_pk)
```

The coordinator simply sums all received `(norm_big_y, norm_big_c)` pairs:

```rust
for (_, participant_output) in
    recv_from_others::<CKDOutput>(&chan, waitpoint, &participants, me).await?
{
    norm_big_y += participant_output.big_y();
    norm_big_c += participant_output.big_c();
}
``` [3](#0-2) 

The `ckd()` entry-point validates participant membership and deduplication, but performs **no check** that `key_pair.public_key` is consistent across participants: [4](#0-3) 

This is the direct analog of the reported Socket/1inch issue: just as `swapExtraData` bytes are used without verifying they match the explicitly passed `toToken`/`receiverAddress`, here `key_pair.public_key` is used in the hash without verifying it matches the master public key all other participants agreed on during DKG.

---

### Impact Explanation

If malicious participant `j` supplies `pk_j ≠ pk` (the true master public key), the aggregated output becomes:

```
big_c_agg = Σ_{i≠j} λ_i · x_i · H(pk ‖ app_id)
          + λ_j · x_j · H(pk_j ‖ app_id)
          + y · app_pk
```

After the client unmasks with `app_sk`:

```
big_c_agg − app_sk · big_y = Σ_{i≠j} λ_i · x_i · H(pk ‖ app_id)
                             + λ_j · x_j · H(pk_j ‖ app_id)
```

This is not equal to `msk · H(pk ‖ app_id)`. The derived confidential key is permanently corrupted. The coordinator and all honest participants accept this output as valid — there is no verification step that would detect the inconsistency. This matches the allowed impact: **High — Corruption of CKD outputs so honest parties accept inconsistent or unusable cryptographic outputs.**

---

### Likelihood Explanation

Any single participant in the CKD session is an attacker-controlled entry point. The `key_pair` argument is caller-supplied with no runtime binding to the DKG transcript. No cryptographic proof ties `key_pair.public_key` to `key_pair.private_share` or to the agreed group public key. The attack requires only that the malicious participant construct a `KeygenOutput` with an arbitrary `public_key` field — a trivial struct manipulation — before calling `ckd()`.

---

### Recommendation

1. **Broadcast and agree on `public_key` before computing the hash.** Add a round in `do_ckd_participant` / `do_ckd_coordinator` where each participant broadcasts their `key_pair.public_key`, and abort if any participant's value differs from the others.
2. **Alternatively**, pass `public_key` as a separate, explicit parameter to `ckd()` (distinct from `key_pair`) so the caller cannot accidentally or maliciously supply a mismatched value embedded inside the opaque `KeygenOutput` struct.
3. At minimum, the coordinator should verify that the `public_key` it uses in its own `compute_signature_share` call matches what it receives from participants — though this requires participants to also transmit their `public_key` alongside `(norm_big_y, norm_big_c)`.

---

### Proof of Concept

```rust
// Honest participants use the true master public key `pk`
let honest_key_pair = KeygenOutput { public_key: pk, private_share: honest_share };

// Malicious participant substitutes an arbitrary public key `pk_evil`
let evil_key_pair = KeygenOutput { public_key: pk_evil, private_share: evil_share };

// All participants call ckd() — no cross-participant pk consistency check exists
let evil_protocol = ckd(&participants, coordinator, evil_me, evil_key_pair, app_id, app_pk, rng).unwrap();

// The coordinator aggregates honest + evil shares without detecting the mismatch.
// The resulting CKDOutput does NOT equal msk * H(pk || app_id).
// The client's unmask() call yields a corrupted, non-reproducible key.
``` [5](#0-4)

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
