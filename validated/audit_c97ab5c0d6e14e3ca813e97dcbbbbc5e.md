### Title
Malicious Participant Can Corrupt CKD Output Without Detection Due to Missing Proof of Correct Computation — (`File: src/confidential_key_derivation/protocol.rs`)

---

### Summary

The Confidential Key Derivation (CKD) coordinator blindly aggregates `(big_y, big_c)` shares received from participants with no cryptographic proof that each share was computed honestly. A single malicious participant can inject arbitrary group elements, causing the coordinator to output a corrupted `CKDOutput` that does not correspond to the real master secret key. The TEE application will silently derive a wrong confidential key.

---

### Finding Description

In `do_ckd_coordinator`, the coordinator collects each participant's `(norm_big_y, norm_big_c)` contribution and sums them unconditionally:

```rust
for (_, participant_output) in
    recv_from_others::<CKDOutput>(&chan, waitpoint, &participants, me).await?
{
    norm_big_y += participant_output.big_y();
    norm_big_c += participant_output.big_c();
}
``` [1](#0-0) 

Each honest participant is supposed to send:

- `norm_big_y = λᵢ · yᵢ · G`
- `norm_big_c = λᵢ · (xᵢ · H(pk ‖ app_id) + yᵢ · app_pk)`

as computed in `compute_signature_share`: [2](#0-1) 

The coordinator has no mechanism to verify that the received `(big_y, big_c)` pair satisfies this relation. There is no zero-knowledge proof of correct ElGamal encryption, no dlog-equality proof binding `big_y` and `big_c` to the same blinding scalar `yᵢ`, and no commitment scheme that would bind the participant to their honest share before the coordinator aggregates.

The `do_ckd_participant` path simply computes and sends the values with no accompanying proof: [3](#0-2) 

The crypto proof infrastructure (`dlogeq.rs`) exists in the repository but is not used here. [4](#0-3) 

---

### Impact Explanation

The final CKD output satisfies the correctness equation only if every participant contributes honestly:

```
C_final − Y_final · app_sk  =  msk · H(pk ‖ app_id)
```

If a malicious participant sends `(big_y + Δ_y, big_c + Δ_c)` for arbitrary group elements `Δ_y, Δ_c`, the coordinator computes:

```
C_final − Y_final · app_sk  =  msk · H(pk ‖ app_id)  +  Δ_c − Δ_y · app_sk
```

The TEE silently derives a wrong confidential key. The coordinator returns `Some(ckd_output)` with no error, so honest parties have no indication the output is invalid.

**Impact category**: High — Corruption of CKD outputs so honest parties accept unusable cryptographic outputs.

---

### Likelihood Explanation

- Any single non-coordinator participant is a sufficient attacker; no collusion is required.
- The attack requires only that the participant deviate from the protocol when calling `ckd()` — a straightforward library-level deviation.
- The coordinator performs no verification and returns success, so the corruption is silent.
- The CKD protocol is designed for TEE-based applications where the confidential key is security-critical; a wrong key silently breaks the application's security guarantees.

---

### Recommendation

Add a zero-knowledge proof of correct ElGamal encryption to each participant's message. Specifically, each participant should prove knowledge of a scalar `yᵢ` such that:

1. `big_y / λᵢ = yᵢ · G` (discrete log of `big_y`)
2. `(big_c − λᵢ · xᵢ · H(pk ‖ app_id)) / λᵢ = yᵢ · app_pk` (same `yᵢ` used in the ciphertext)

This is a standard dlog-equality (Chaum–Pedersen) proof over `(G, app_pk)`, which the existing `dlogeq.rs` infrastructure already supports. The coordinator must verify this proof before accepting any participant's contribution.

Alternatively, restructure the protocol so participants commit to their `(big_y, big_c)` values in a first round (as done in DKG via `commitment_hash`), reveal in a second round, and the coordinator verifies the opening before aggregating.

---

### Proof of Concept

1. Honest participants `P1, P2` and malicious participant `P3` run `ckd()` with a shared master key.
2. `P3` overrides the `compute_signature_share` result and instead sends `(big_y = G, big_c = G)` (arbitrary non-zero group elements) to the coordinator.
3. The coordinator executes:
   ```rust
   norm_big_y += participant_output.big_y(); // adds G
   norm_big_c += participant_output.big_c(); // adds G
   ``` [5](#0-4) 
4. The coordinator returns `Some(CKDOutput::new(norm_big_y, norm_big_c))` with no error. [6](#0-5) 
5. The TEE calls `ckd_output.unmask(app_sk)` and obtains `msk · H(pk ‖ app_id) + G − G · app_sk`, which is not the intended confidential key. The TEE has no way to detect this.

### Citations

**File:** src/confidential_key_derivation/protocol.rs (L27-32)
```rust
    let (norm_big_y, norm_big_c) =
        compute_signature_share(participants, me, key_pair, app_id, app_pk, rng)?;
    let waitpoint = chan.next_waitpoint();
    chan.send_private(waitpoint, coordinator, &(norm_big_y, norm_big_c))?;

    Ok(None)
```

**File:** src/confidential_key_derivation/protocol.rs (L50-55)
```rust
    for (_, participant_output) in
        recv_from_others::<CKDOutput>(&chan, waitpoint, &participants, me).await?
    {
        norm_big_y += participant_output.big_y();
        norm_big_c += participant_output.big_c();
    }
```

**File:** src/confidential_key_derivation/protocol.rs (L56-57)
```rust
    let ckd_output = CKDOutput::new(norm_big_y, norm_big_c);
    Ok(Some(ckd_output))
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

**File:** src/crypto/proofs/dlogeq.rs (L1-5)
```rust
use super::strobe_transcript::Transcript;
use crate::{
    crypto::constants::{
        NEAR_DLOGEQ_CHALLENGE_LABEL, NEAR_DLOGEQ_COMMITMENT_LABEL,
        NEAR_DLOGEQ_ENCODE_LABEL_GENERATOR1, NEAR_DLOGEQ_ENCODE_LABEL_PUBLIC0,
```
