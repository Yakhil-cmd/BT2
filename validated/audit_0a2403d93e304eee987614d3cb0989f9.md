Looking at the CKD protocol's coordinator aggregation logic in `src/confidential_key_derivation/protocol.rs`: [1](#0-0) 

The `do_ckd_coordinator` function receives `(norm_big_y, norm_big_c)` from each participant and sums them with no proof-of-correctness check: [2](#0-1) 

Each participant computes their contribution via `compute_signature_share`, which derives values from their secret share and a random blinding factor: [3](#0-2) 

No ZK proof or DLEQ proof is attached to the contribution, and the coordinator never verifies correctness before aggregating.

---

### Title
CKD Coordinator Accepts Unverified Participant Contributions, Enabling CKD Output Corruption — (File: `src/confidential_key_derivation/protocol.rs`)

### Summary
The `do_ckd_coordinator` function aggregates participant-supplied group elements into the final `CKDOutput` without any proof of correctness. A single malicious participant can send arbitrary elliptic-curve points, causing the coordinator to output a corrupted derived key that honest parties accept as valid.

### Finding Description
In `do_ckd_coordinator` (lines 50–55), the coordinator iterates over messages received from all other participants and unconditionally adds each `big_y` and `big_c` to the running aggregate:

```rust
for (_, participant_output) in
    recv_from_others::<CKDOutput>(&chan, waitpoint, &participants, me).await?
{
    norm_big_y += participant_output.big_y();
    norm_big_c += participant_output.big_c();
}
```

Each participant is supposed to compute:
- `norm_big_y = λ_i · y_i · G`
- `norm_big_c = λ_i · (x_i · H(pk ‖ app_id) + y_i · app_pk)`

where `x_i` is their secret share and `y_i` is a fresh random blinding scalar. However, `compute_signature_share` (lines 148–181) produces these values locally and sends them with no attached proof of knowledge or DLEQ proof. The coordinator has no mechanism to distinguish a correctly-computed contribution from an arbitrary pair of group elements. This is the direct analog of the `cancelOrder` pattern: participant state (the contribution) is recorded and used, but the validity of that state is never checked.

### Impact Explanation
A malicious participant sends arbitrary `(R₁, R₂) ∈ G₁²` instead of their correct `(norm_big_y, norm_big_c)`. The coordinator outputs:

```
final_big_y = Σ(correct_y_i) + R₁
final_big_c = Σ(correct_c_i) + R₂
```

The resulting `CKDOutput` does not correspond to the correct threshold-derived confidential key. Any downstream consumer (e.g., a TEE decrypting with `app_sk`) will obtain a wrong or random key. This matches the allowed High impact: **Corruption of CKD outputs so honest parties accept unusable cryptographic outputs**.

### Likelihood Explanation
The attack requires only one malicious participant in the CKD session. The protocol is a single-round aggregation with no abort or complaint mechanism. The malicious participant needs only to deviate in the one message they send to the coordinator — no special cryptographic capability is required.

### Recommendation
Attach a DLEQ (Discrete Log Equality) proof or Schnorr proof of knowledge to each participant's contribution, proving that `norm_big_c` was computed from the same secret share committed to during DKG. The coordinator should verify each proof before adding the contribution to the aggregate, and abort if any proof fails.

### Proof of Concept
1. N honest participants and one malicious participant P_m run the CKD protocol.
2. Honest participants call `compute_signature_share` and send correct `(norm_big_y, norm_big_c)` to the coordinator.
3. P_m instead sends `(R₁, R₂)` — two arbitrary points in G₁ — to the coordinator via `chan.send_private(waitpoint, coordinator, &(R₁, R₂))`.
4. In `do_ckd_coordinator`, the loop at lines 50–55 adds `R₁` and `R₂` to the running sums without any check.
5. The coordinator returns a `CKDOutput` containing `(Σ norm_big_y + R₁, Σ norm_big_c + R₂)`.
6. The honest coordinator outputs this corrupted value as the final CKD result; `ckd_output.unmask(app_sk)` yields a wrong key, silently corrupting the derived secret for all consumers. [4](#0-3) [3](#0-2)

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

**File:** src/confidential_key_derivation/protocol.rs (L148-181)
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
```
