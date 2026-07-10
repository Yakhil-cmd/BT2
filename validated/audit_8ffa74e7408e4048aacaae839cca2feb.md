### Title
Malicious Participant Can Corrupt CKD Output Without Detection — (`File: src/confidential_key_derivation/protocol.rs`)

### Summary
In the Confidential Key Derivation (CKD) protocol, the coordinator blindly aggregates `(big_y, big_c)` contributions from all participants with no cryptographic proof of correct computation. A single malicious participant can send arbitrary group elements, silently corrupting the final derived confidential key accepted by the coordinator.

### Finding Description

In `do_ckd_coordinator`, the coordinator receives each participant's `CKDOutput` and unconditionally adds the components together: [1](#0-0) 

Each participant is supposed to compute, in `compute_signature_share`:

- `big_y = lambda_i * y_i * G` (Lagrange-weighted random blinding point)
- `big_c = lambda_i * (x_i * H(pk, app_id) + y_i * app_pk)` (Lagrange-weighted ElGamal ciphertext share) [2](#0-1) 

However, no zero-knowledge proof or any other verification is attached to the sent `(big_y, big_c)` pair. The coordinator has no way to check that the received values were honestly derived from the participant's actual key share `x_i` and a fresh random `y_i`. A malicious participant simply sends any two group elements of their choice, and the coordinator adds them in without complaint. [3](#0-2) 

The correct final output satisfies:

```
C_final - app_sk * Y_final = msk * H(pk, app_id)
```

where `msk` is the master secret key. If any participant substitutes arbitrary `(big_y', big_c')`, the coordinator computes a corrupted `(Y_final, C_final)` that no longer satisfies this relation, producing an incorrect confidential key that the coordinator accepts as valid.

### Impact Explanation

**High — Corruption of CKD outputs so honest parties accept incorrect/unusable cryptographic outputs.**

The coordinator, which is the sole recipient of the final `CKDOutput`, will return a silently wrong derived key to the application. The application has no mechanism to detect this corruption because the correctness of the CKD output can only be verified by the entity holding `app_sk`, and even then only after the fact. Any TEE or downstream consumer relying on the derived key will operate on a corrupted secret, rendering the CKD protocol's output useless or, worse, predictably wrong in a way the malicious participant controls additively.

### Likelihood Explanation

Any single participant in the CKD protocol can trigger this. The attacker-controlled entry path is direct: a participant calls `ckd(...)`, receives a `waitpoint`, and sends a crafted `CKDOutput` to the coordinator instead of the honest computation. No special privilege, leaked key, or external assumption is required — only participation in the protocol. [4](#0-3) 

### Recommendation

Require each participant to accompany their `(big_y, big_c)` contribution with a non-interactive zero-knowledge proof of correct formation — specifically, a proof of knowledge of `(x_i, y_i)` such that:

- `big_y = lambda_i * y_i * G`
- `big_c = lambda_i * (x_i * H(pk, app_id) + y_i * app_pk)`
- `x_i` is consistent with the participant's public verification share from the DKG output

The coordinator must verify all such proofs before aggregating contributions. This is the standard approach used in threshold BLS signature schemes (e.g., a Chaum-Pedersen DLEQ proof relating `big_y` and the `y_i * app_pk` component of `big_c`).

### Proof of Concept

1. Honest participants run `ckd(...)` and send correct `(norm_big_y, norm_big_c)` to the coordinator.
2. Malicious participant `P_m` instead sends `(ElementG1::identity(), ElementG1::identity())` — the group identity — to the coordinator.
3. The coordinator loop at line 53–54 adds these zero elements in:
   ```rust
   norm_big_y += participant_output.big_y();  // += identity → no change to Y
   norm_big_c += participant_output.big_c();  // += identity → removes P_m's BLS share from C
   ```
4. The resulting `CKDOutput` is missing `P_m`'s Lagrange-weighted BLS signature share, so `C_final - app_sk * Y_final ≠ msk * H(pk, app_id)`.
5. The coordinator returns this corrupted output with no error, and the application derives an incorrect confidential key. [5](#0-4)

### Citations

**File:** src/confidential_key_derivation/protocol.rs (L17-33)
```rust
fn do_ckd_participant(
    mut chan: SharedChannel,
    participants: &ParticipantList,
    coordinator: Participant,
    me: Participant,
    key_pair: &KeygenOutput,
    app_id: &AppId,
    app_pk: PublicKey,
    rng: &mut impl CryptoRngCore,
) -> Result<CKDOutputOption, ProtocolError> {
    let (norm_big_y, norm_big_c) =
        compute_signature_share(participants, me, key_pair, app_id, app_pk, rng)?;
    let waitpoint = chan.next_waitpoint();
    chan.send_private(waitpoint, coordinator, &(norm_big_y, norm_big_c))?;

    Ok(None)
}
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
