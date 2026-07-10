### Title
Malicious Participant Can Corrupt CKD Output via Inconsistent Public Key in Hash Computation - (File: `src/confidential_key_derivation/protocol.rs`)

---

### Summary

In the Confidential Key Derivation (CKD) protocol, each participant computes a signature share using `hash_app_id_with_pk(&key_pair.public_key, app_id)`. The `public_key` field of `KeygenOutput` is caller-supplied and is never validated against the actual aggregate public key or cross-checked with other participants. A malicious participant can supply a `KeygenOutput` with a different `public_key`, causing their hash point to diverge from the one used by honest participants and by the verifier. The coordinator blindly aggregates all shares, producing a `CKDOutput` that is permanently unusable.

---

### Finding Description

The `ckd()` entry point in `src/confidential_key_derivation/protocol.rs` accepts a `key_pair: KeygenOutput` from the caller. Inside `compute_signature_share`, the aggregate public key embedded in `key_pair.public_key` is used to compute the hash point:

```rust
// src/confidential_key_derivation/protocol.rs, lines 167-171
let hash_point = hash_app_id_with_pk(&key_pair.public_key, app_id);
let big_s = hash_point * private_share.to_scalar();
let big_c = big_s + app_pk * y.0;
``` [1](#0-0) 

The function `hash_app_id_with_pk` is defined as `H(pk || app_id)`:

```rust
// src/confidential_key_derivation/mod.rs, lines 67-70
pub fn hash_app_id_with_pk(pk: &VerifyingKey, app_id: &[u8]) -> ElementG1 {
    let compressed_pk = pk.to_element().to_compressed();
    let input = [compressed_pk.as_slice(), app_id].concat();
    ciphersuite::hash_to_curve(&input)
}
``` [2](#0-1) 

The `ckd()` function performs no validation that `key_pair.public_key` is consistent with `key_pair.private_share`, nor that it matches the `public_key` used by other participants:

```rust
// src/confidential_key_derivation/protocol.rs, lines 66-101
pub fn ckd(
    participants: &[Participant],
    coordinator: Participant,
    me: Participant,
    key_pair: KeygenOutput,   // <-- public_key is never validated
    app_id: impl Into<AppId>,
    app_pk: PublicKey,
    ...
``` [3](#0-2) 

The coordinator aggregates shares from all participants without any proof that each participant used the correct `public_key`:

```rust
// src/confidential_key_derivation/protocol.rs, lines 50-56
for (_, participant_output) in
    recv_from_others::<CKDOutput>(&chan, waitpoint, &participants, me).await?
{
    norm_big_y += participant_output.big_y();
    norm_big_c += participant_output.big_c();
}
``` [4](#0-3) 

The verification path (`verify_signature` in `src/confidential_key_derivation/ciphersuite.rs`) independently recomputes `hash_app_id_with_pk(verifying_key, msg)` using the verifier's own `verifying_key`:

```rust
// src/confidential_key_derivation/ciphersuite.rs, lines 234-239
let base1 = hash_app_id_with_pk(verifying_key, msg).into();
...
if blstrs::pairing(&base1, &element2).eq(&blstrs::pairing(&element1, &base2)) {
    Ok(())
} else {
    Err(frost_core::Error::InvalidSignature)
}
``` [5](#0-4) 

This creates two independent paths that must agree on the same `public_key` but have no mechanism to enforce it:

- **Share-computation path**: uses `key_pair.public_key` (caller-supplied, per-participant)
- **Verification path**: uses `verifying_key` (caller-supplied to verifier)

---

### Impact Explanation

A malicious participant supplies a `KeygenOutput` where `public_key = pk'` (any point different from the true aggregate key `pk`). Their contribution becomes:

```
big_s'  = H(pk' || app_id) * x_i          (wrong hash point)
big_c'  = big_s' + app_pk * y_i
```

The coordinator sums all Lagrange-weighted contributions. Because one term uses `H(pk' || app_id)` instead of `H(pk || app_id)`, the aggregated `big_c` is:

```
Σ λ_i * big_c_i  ≠  msk * H(pk || app_id) + app_pk * Σ λ_i * y_i
```

When the client unmasks with `big_c - app_sk * big_y`, the result is not `msk * H(pk || app_id)`. The `CKDOutput` is permanently corrupted and verification via `verify_signature` will fail. Honest parties cannot recover the correct confidential key.

**Impact class**: High — Corruption of CKD output so honest parties accept an unusable cryptographic output.

---

### Likelihood Explanation

Any participant in the CKD protocol can trigger this by constructing a `KeygenOutput` with an arbitrary `public_key`. No special privilege is required beyond being a valid participant. The attack requires only that the malicious party call `ckd()` with a modified `key_pair.public_key`. The coordinator has no mechanism to detect the inconsistency because no zero-knowledge proof or commitment binds `public_key` to `private_share` in the CKD protocol inputs.

---

### Recommendation

Before using `key_pair.public_key` in `compute_signature_share`, validate that it is consistent with `key_pair.private_share` (i.e., that `private_share * G2_generator` lies on the correct commitment polynomial). Alternatively, require participants to broadcast their claimed `public_key` and have the coordinator reject any participant whose claimed key differs from the expected aggregate key. A zero-knowledge proof binding `public_key` to `private_share` (analogous to the proof-of-knowledge already used in DKG) would close this gap.

---

### Proof of Concept

1. Honest DKG produces `(x_1, pk)`, `(x_2, pk)`, `(x_3, pk)` for three participants with aggregate key `pk = msk * G2`.
2. Malicious participant 1 constructs `key_pair_bad = KeygenOutput { private_share: x_1, public_key: pk' }` where `pk' ≠ pk`.
3. Participant 1 calls `ckd(participants, coordinator, p1, key_pair_bad, app_id, app_pk, rng)`.
4. Inside `compute_signature_share`, participant 1 computes `hash_point = H(pk' || app_id)` instead of `H(pk || app_id)`.
5. Participant 1 sends `(λ_1 * Y_1, λ_1 * (hash_point * x_1 + app_pk * y_1))` to the coordinator.
6. The coordinator aggregates all three shares. The resulting `big_c` is:
   ```
   λ_1*(H(pk'||app_id)*x_1 + app_pk*y_1) + λ_2*(H(pk||app_id)*x_2 + app_pk*y_2) + λ_3*(H(pk||app_id)*x_3 + app_pk*y_3)
   ```
   which is not equal to `msk * H(pk || app_id) + app_pk * Σ λ_i * y_i`.
7. The client calls `ckd_output.unmask(app_sk)` and obtains a garbage value. `verify_signature(&pk, app_id, &result)` returns `InvalidSignature`.
8. The CKD session is permanently corrupted for this request.

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

**File:** src/confidential_key_derivation/protocol.rs (L167-174)
```rust
    // H(pk || app_id) when H is a random oracle
    let hash_point = hash_app_id_with_pk(&key_pair.public_key, app_id);

    // S <- x . H(app_id)
    let big_s = hash_point * private_share.to_scalar();

    // C <- S + y . A
    let big_c = big_s + app_pk * y.0;
```

**File:** src/confidential_key_derivation/mod.rs (L67-71)
```rust
pub fn hash_app_id_with_pk(pk: &VerifyingKey, app_id: &[u8]) -> ElementG1 {
    let compressed_pk = pk.to_element().to_compressed();
    let input = [compressed_pk.as_slice(), app_id].concat();
    ciphersuite::hash_to_curve(&input)
}
```

**File:** src/confidential_key_derivation/ciphersuite.rs (L234-243)
```rust
    let base1 = hash_app_id_with_pk(verifying_key, msg).into();
    let base2 =
        <<BLS12381SHA256 as frost_core::Ciphersuite>::Group as frost_core::Group>::generator()
            .into();

    if blstrs::pairing(&base1, &element2).eq(&blstrs::pairing(&element1, &base2)) {
        Ok(())
    } else {
        Err(frost_core::Error::InvalidSignature)
    }
```
