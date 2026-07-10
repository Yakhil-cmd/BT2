### Title
Malicious CKD Participant Can Submit Arbitrary Contributions Without Cryptographic Verification, Corrupting the Derived Key — (File: `src/confidential_key_derivation/protocol.rs`)

---

### Summary

The CKD coordinator aggregates participant contributions without any cryptographic verification. A single malicious participant can send arbitrary group elements in place of their honest contribution, causing the coordinator to output a corrupted derived key that the TEE will silently accept as correct.

---

### Finding Description

In `do_ckd_coordinator`, the coordinator receives `(norm_big_y, norm_big_c)` from every other participant and unconditionally sums them: [1](#0-0) 

```rust
for (_, participant_output) in
    recv_from_others::<CKDOutput>(&chan, waitpoint, &participants, me).await?
{
    norm_big_y += participant_output.big_y();
    norm_big_c += participant_output.big_c();
}
```

Each honest participant is supposed to compute in `compute_signature_share`: [2](#0-1) 

- `norm_big_y = lambda_i * y_i * G1` (ElGamal nonce commitment)
- `norm_big_c = lambda_i * (private_share_i * H(pk || app_id) + y_i * app_pk)` (encrypted BLS signature share)

The coordinator has all the information needed to verify each contribution via a pairing check:

```
e(norm_big_c_i − norm_big_y_i * app_pk, G2) = e(H(pk ∥ app_id), λ_i * public_share_i)
```

This check is entirely absent. There is no proof of correct computation, no commitment scheme, and no consistency check of any kind before the contributions are folded into the final output. [3](#0-2) 

---

### Impact Explanation

A malicious participant sends `norm_big_c' = norm_big_c + δ` for any att

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

**File:** src/confidential_key_derivation/protocol.rs (L165-180)
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
```
