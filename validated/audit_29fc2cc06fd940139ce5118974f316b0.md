### Title
Unverified CKD Participant Contributions Allow Malicious Participant to Corrupt Coordinator Output - (File: src/confidential_key_derivation/protocol.rs)

### Summary
The CKD coordinator accumulates cryptographic contributions `(norm_big_y, norm_big_c)` from each participant with no zero-knowledge proof or consistency check. A single malicious participant can send arbitrary group elements, causing the coordinator to output a corrupted `CKDOutput` that decrypts to a wrong confidential key.

### Finding Description

In `do_ckd_coordinator`, the coordinator receives each participant's `(norm_big_y, norm_big_c)` pair and blindly adds them together:

```rust
for (_, participant_output) in
    recv_from_others::<CKDOutput>(&chan, waitpoint, &participants, me).await?
{
    norm_big_y += participant_output.big_y();
    norm_big_c += participant_output.big_c();
}
``` [1](#0-0) 

No proof is required that `norm_big_c` was formed as `lambda_i * (x_i * H(pk, app_id) + y_i * app_pk)` or that `norm_big_y` was formed as `lambda_i * y_i * G`. The coordinator simply trusts the claimed values.

The correct protocol requires each participant `i` to compute:

- `big_y = y_i * G`
- `big_s = x_i * H(pk, app_id)`
- `big_c = big_s + y_i * app_pk`
- `norm_big_y = lambda_i * big_y`, `norm_big_c = lambda_i * big_c` [2](#0-1) 

The coordinator then sums these to reconstruct `C = msk * H(pk, app_id) + Y * app_pk`, from which the application recovers `confidential_key = C - app_sk * Y`. If any participant sends `(norm_big_y + delta_y, norm_big_c + delta_c)` for arbitrary deltas, the final output becomes `C' = C_correct + delta_c` and `Y' = Y_correct + delta_y`, yielding a wrong confidential key `msk * H(pk, app_id) + delta_c - app_sk * delta_y`.

This is the direct analog of the Sherlock/Balancer bookkeeping bug: just as that system tracked token balances internally without verifying actual transfer amounts, the CKD coordinator tracks cryptographic contributions internally without verifying they are correctly formed relative to each participant's committed key share.

### Impact Explanation

A malicious participant causes the coordinator to accept and output a corrupted `CKDOutput`. All honest parties that rely on this output will derive a wrong confidential key. The output is silently wrong — there is no error returned, and the coordinator has no way to detect the corruption. This matches the allowed High impact: **Corruption of CKD outputs so honest parties accept unusable cryptographic outputs**.

### Likelihood Explanation

Any single participant in the CKD protocol can trigger this. The attacker-controlled entry path is straightforward: call `ckd()` as a legitimate participant, then send a malformed `(norm_big_y, norm_big_c)` to the coordinator instead of the correctly computed values. No special privilege, leaked key, or cryptographic break is required — only participation in the protocol. [3](#0-2) 

### Recommendation

Each participant must accompany their `(norm_big_y, norm_big_c)` with a non-interactive zero-knowledge proof of correct formation. Concretely, a Chaum-Pedersen proof can demonstrate that:

1. `norm_big_y / lambda_i` and `norm_big_c / lambda_i - x_i * H(pk, app_id)` share the same discrete log `y_i` relative to `G` and `app_pk` respectively.
2. The `x_i` used is consistent with the participant's public key share from DKG.

The coordinator must verify all such proofs before accumulating contributions.

### Proof of Concept

1. Honest participants `P_1, ..., P_{n-1}` and malicious participant `P_n` run `ckd()`.
2. `P_n` computes the correct `(norm_big_y_n, norm_big_c_n)` but instead sends `(norm_big_y_n + delta_y, norm_big_c_n + delta_c)` for arbitrary non-zero `delta_y, delta_c` to the coordinator.
3. The coordinator at line 53–54 adds these without verification:
   - `norm_big_y += norm_big_y_n + delta_y` → final `Y' = Y_correct + delta_y`
   - `norm_big_c += norm_big_c_n + delta_c` → final `C' = C_correct + delta_c`
4. `CKDOutput::new(norm_big_y', norm_big_c')` is returned as `Some(ckd_output)`.
5. The application calls `ckd_output.unmask(app_sk)` and obtains `C' - app_sk * Y' = msk * H(pk, app_id) + delta_c - app_sk * delta_y`, which is not the correct confidential key. [4](#0-3)

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
