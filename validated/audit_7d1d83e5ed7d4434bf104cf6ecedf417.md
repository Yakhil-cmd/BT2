### Title
Missing Validation of Participant-Supplied `key_pair.public_key` in CKD Coordinator Allows Malicious Participant to Corrupt CKD Output — (File: `src/confidential_key_derivation/protocol.rs`)

---

### Summary

The `ckd()` entry point accepts a caller-supplied `key_pair: KeygenOutput` without verifying that `key_pair.public_key` matches any agreed-upon master public key. Inside `do_ckd_coordinator()`, the coordinator accumulates `(norm_big_y, norm_big_c)` tuples received from every participant with no zero-knowledge proof, no commitment binding, and no consistency check against the expected group public key. A malicious participant can supply a `KeygenOutput` whose `public_key` field is an arbitrary curve point, causing `compute_signature_share()` to hash a wrong key and produce a corrupted contribution. Because the coordinator blindly sums all contributions, the final `CKDOutput` is silently wrong, and every honest party that calls `unmask()` on it derives an incorrect confidential key.

---

### Finding Description

In `compute_signature_share()`, the hash point that anchors the entire derivation is computed as:

```rust
let hash_point = hash_app_id_with_pk(&key_pair.public_key, app_id);
let big_s = hash_point * private_share.to_scalar();
``` [1](#0-0) 

`hash_app_id_with_pk` concatenates the compressed encoding of `key_pair.public_key` with `app_id` and hashes to a G1 curve point:

```rust
pub fn hash_app_id_with_pk(pk: &VerifyingKey, app_id: &[u8]) -> ElementG1 {
    let compressed_pk = pk.to_element().to_compressed();
    let input = [compressed_pk.as_slice(), app_id].concat();
    ciphersuite::hash_to_curve(&input)
}
``` [2](#0-1) 

The correctness of the entire CKD derivation depends on every participant using the **same** `public_key` (the master public key produced by DKG). However, `ckd()` performs no check that `key_pair.public_key` equals any expected value — it only validates the participant list structure: [3](#0-2) 

In `do_ckd_coordinator()`, the coordinator receives each participant's `(norm_big_y, norm_big_c)` and adds them unconditionally:

```rust
for (_, participant_output) in
    recv_from_others::<CKDOutput>(&chan, waitpoint, &participants, me).await?
{
    norm_big_y += participant_output.big_y();
    norm_big_c += participant_output.big_c();
}
``` [4](#0-3) 

There is no proof of correct computation, no commitment binding the contribution to the agreed public key, and no cross-check against the expected group public key. This is structurally identical to the Symmetry `buy_state_rebalance` pattern: data is forwarded to a sub-computation without validating that the inputs correspond to the expected cryptographic context. The coordinator only checks that it receives a response from every participant — it does not check *what* those responses contain.

---

### Impact Explanation

A single malicious participant substitutes `PK'` (any curve point they choose) for the real master public key `PK` in their `KeygenOutput`. Their contribution becomes:

```
lambda_M * (H(PK' || app_id) * x_M + app_pk * y_M)
```

instead of the correct:

```
lambda_M * (H(PK || app_id) * x_M + app_pk * y_M)
```

The coordinator sums this with the honest contributions and produces a `CKDOutput` whose `big_c` field is not equal to `H(PK

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

**File:** src/confidential_key_derivation/protocol.rs (L167-171)
```rust
    // H(pk || app_id) when H is a random oracle
    let hash_point = hash_app_id_with_pk(&key_pair.public_key, app_id);

    // S <- x . H(app_id)
    let big_s = hash_point * private_share.to_scalar();
```

**File:** src/confidential_key_derivation/mod.rs (L67-71)
```rust
pub fn hash_app_id_with_pk(pk: &VerifyingKey, app_id: &[u8]) -> ElementG1 {
    let compressed_pk = pk.to_element().to_compressed();
    let input = [compressed_pk.as_slice(), app_id].concat();
    ciphersuite::hash_to_curve(&input)
}
```
