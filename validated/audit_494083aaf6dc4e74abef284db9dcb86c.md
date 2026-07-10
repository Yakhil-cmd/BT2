Looking at the CKD protocol in `src/confidential_key_derivation/protocol.rs`, specifically `do_ckd_coordinator`.

---

### Title
Missing Validation of CKD Share Correctness in `do_ckd_coordinator` Allows Any Malicious Participant to Corrupt the Derived Key Output — (File: `src/confidential_key_derivation/protocol.rs`)

---

### Summary

In `do_ckd_coordinator`, the coordinator collects `CKDOutput` shares from all participants and blindly accumulates them with no cryptographic proof of correctness. The sender identity is explicitly discarded (`for (_, participant_output)`). Any single malicious participant in the set can send an arbitrary `(norm_big_y, norm_big_c)` pair, causing the coordinator to produce a corrupted CKD output that honest parties will accept as valid.

---

### Finding Description

`do_ckd_coordinator` receives one `CKDOutput` per participant via `recv_from_others` and sums them:

```rust
for (_, participant_output) in
    recv_from_others::<CKDOutput>(&chan, waitpoint, &participants, me).await?
{
    norm_big_y += participant_output.big_y();
    norm_big_c += participant_output.big_c();
}
let ckd_output = CKDOutput::new(norm_big_y, norm_big_c);
``` [1](#0-0) 

The sender identity is thrown away (`_`). No zero-knowledge proof, commitment, or any other check is performed to verify that the received `(norm_big_y, norm_big_c)` was honestly computed from the participant's actual key share `x_i`, the correct `app_id`, and the correct `app_pk`.

The correct computation each participant should perform is:

```
norm_big_y = λ_i · (y_i · G)
norm_big_c = λ_i · (x_i · H(pk, app_id) + y_i · app_pk)
``` [2](#0-1) 

A malicious participant can instead send any group elements `(Y', C')` of their choosing. The coordinator has no mechanism to detect this.

The analog to the external report is direct: just as `op::burn_notification` accepted a `new_supply` from any sender without checking `sender_address == jetton_master_address`, `do_ckd_coordinator` accepts `(norm_big_y, norm_big_c)` from any participant without checking that the values are correctly derived from that participant's committed key share.

---

### Impact Explanation

The final CKD output is an ElGamal encryption of `msk · H(pk, app_id)` under `app_pk`. When the coordinator sums all shares:

```
total_big_c = msk · H(pk, app_id) + (Σ λ_i · y_i) · app_pk
```

If one participant substitutes an arbitrary `C'` for their honest `norm_big_c`, the sum becomes:

```
total_big_c' = (msk - λ_i · x_i) · H(pk, app_id) + λ_i · C'_offset + ...
```

The application decrypts this with `app_sk` and obtains a value that is **not** `msk · H(pk, app_id)`. The coordinator returns this corrupted value as `Some(ckd_output)` with no error, and honest parties have no way to detect the corruption.

**Impact class:** High — Corruption of CKD outputs so honest parties accept an incorrect derived key, matching the allowed scope: *"Corruption of DKG, reshare, refresh, presign, sign, or CKD outputs so honest parties accept inconsistent public keys, participant sets, transcripts, or unusable cryptographic outputs."* [3](#0-2) 

---

### Likelihood Explanation

- **One malicious participant is sufficient.** The threshold model does not protect against this because the corruption happens at the coordinator's aggregation step, not at the secret-sharing layer.
- **No special privileges required.** Any participant in the `participants` list can send an arbitrary `CKDOutput`. The `recv_from_others` helper only enforces that exactly one message per known participant is accepted; it does not validate message content.
- **Undetectable by honest parties.** The coordinator returns `Some(ckd_output)` unconditionally. There is no broadcast or consistency check after aggregation. [4](#0-3) 

---

### Recommendation

Each participant must accompany their `(norm_big_y, norm_big_c)` with a zero-knowledge proof of correct computation — specifically, a proof that `norm_big_c` was formed using the same discrete-log witness as the participant's committed public key share. A standard approach is a Chaum–Pedersen proof binding `norm_big_y` and `norm_big_c` to the participant's public share commitment. The coordinator must verify all proofs before accumulating any share.

---

### Proof of Concept

1. Honest participants `P_1, …, P_{n-1}` run `compute_signature_share` correctly and send their outputs to the coordinator.
2. Malicious participant `P_n` (a valid member of `participants`) instead sends `(norm_big_y = G, norm_big_c = G)` — arbitrary group elements unrelated to their key share.
3. The coordinator's `recv_from_others` accepts this message (sender is a known participant, no duplicate).
4. The coordinator adds `G` to both running sums, producing `total_big_y` and `total_big_c` that are offset by `G` from the correct values.
5. The coordinator returns `Some(CKDOutput::new(total_big_y, total_big_c))`.
6. The application calls `ckd_output.unmask(app_sk)` and obtains `msk · H(pk, app_id) + (1 - app_sk) · G` — a value that is not the intended confidential derived key.
7. No error is raised anywhere in the protocol. [5](#0-4)

### Citations

**File:** src/confidential_key_derivation/protocol.rs (L35-57)
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

**File:** src/protocol/helpers.rs (L6-26)
```rust
pub async fn recv_from_others<T>(
    chan: &SharedChannel,
    waitpoint: u64,
    participants: &ParticipantList,
    me: Participant,
) -> Result<Vec<(Participant, T)>, ProtocolError>
where
    T: serde::de::DeserializeOwned,
{
    let mut seen = ParticipantCounter::new(participants);
    seen.put(me);
    let mut messages = Vec::with_capacity(participants.others(me).count());

    while !seen.full() {
        let (from, msg) = chan.recv(waitpoint).await?;
        if seen.put(from) {
            messages.push((from, msg));
        }
    }

    Ok(messages)
```
