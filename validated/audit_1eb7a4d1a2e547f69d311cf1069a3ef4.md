### Title
Missing Cryptographic Verification of Participant Contributions in CKD Coordinator Allows Malicious Participant to Corrupt Confidential Key Derivation Output - (`File: src/confidential_key_derivation/protocol.rs`)

---

### Summary

The `do_ckd_coordinator` function collects `(big_y, big_c)` share contributions from all participants and sums them to produce the final `CKDOutput`, but performs **no cryptographic verification** that each contribution was correctly computed from the participant's actual private share. A malicious participant can send arbitrary group elements, causing the coordinator to output a silently corrupted confidential key derivation result that all honest parties will accept as valid.

---

### Finding Description

The CKD protocol is designed so that each participant computes a share contribution in `compute_signature_share`:

```
big_y  = y * G                          (random blinding)
big_s  = x_i * H(pk || app_id)         (private share contribution)
big_c  = big_s + app_pk * y            (masked share)
norm_big_y = λ_i * big_y
norm_big_c = λ_i * big_c
```

The coordinator is supposed to sum all `norm_big_y` and `norm_big_c` values so that `unmask(app_sk)` recovers `msk * H(pk || app_id)`.

In `do_ckd_coordinator` (lines 50–55), the coordinator receives these values and sums them with no verification whatsoever:

```rust
for (_, participant_output) in
    recv_from_others::<CKDOutput>(&chan, waitpoint, &participants, me).await?
{
    norm_big_y += participant_output.big_y();
    norm_big_c += participant_output.big_c();
}
```

Two critical omissions are present:

1. **The sender identity is discarded** (`_`). The coordinator does not track which participant sent which contribution, making it impossible to attribute or audit a malformed share.

2. **No proof of correct computation is required or checked.** There is no zero-knowledge proof (e.g., a Sigma protocol) that the received `big_c` was computed as `x_i * H(pk || app_id) + app_pk * y` for the participant's actual private share `x_i`, or that `big_y = y * G` for the same `y`. The coordinator blindly accepts any group elements.

This is directly analogous to the external report: just as `retrieveFromStrategy` accepted an arbitrary `from` address without checking that `msg.sender` was authorized to act on behalf of that address, `do_ckd_coordinator` accepts arbitrary cryptographic contributions without checking that they were authorized (i.e., correctly derived) from the participant's actual key share.

---

### Impact Explanation

A malicious participant sends arbitrary `(big_y', big_c')` values — for example, `(G, G)` — instead of correctly computed ones. The coordinator sums these with honest participants' values:

```
sum_norm_big_y = (honest sum) + G
sum_norm_big_c = (honest sum) + G
```

When the application calls `ckd_output.unmask(app_sk)`, it computes:

```
big_c - app_sk * big_y
= (honest_c + G) - app_sk * (honest_y + G)
= msk * H(pk || app_id) + G - app_sk * G
= msk * H(pk || app_id) + (1 - app_sk) * G
```

This is **not** `msk * H(pk || app_id)`. The derived confidential key is silently wrong. No error is raised. All honest parties — including the coordinator — accept this corrupted output as the legitimate CKD result.

**Impact class**: High — Corruption of CKD outputs so honest parties accept an incorrect derived confidential key.

---

### Likelihood Explanation

Any single participant in the CKD protocol can trigger this. The attacker only needs to be a valid member of the participant set (no privileged access required). They run a modified client that sends crafted `(big_y, big_c)` values instead of correctly computed ones. The authenticated channel layer only guarantees the sender's identity, not the correctness of the message content. Since the coordinator performs no content verification, the attack succeeds unconditionally with a single malicious participant.

---

### Recommendation

Each participant must accompany their `(norm_big_y, norm_big_c)` contribution with a zero-knowledge proof of correct computation. Concretely, a Sigma protocol (proof of discrete log equality / Chaum-Pedersen) should prove:

- `big_y = y * G` and `big_c - big_s = y * app_pk` for the same witness `y`, where `big_s = x_i * H(pk || app_id)` is derivable from the participant's public commitment.

The coordinator must verify this proof for every received contribution before adding it to the running sum. Contributions that fail verification should be rejected and the protocol aborted, identifying the malicious participant.

Additionally, the sender identity (`_`) should be retained and logged so that a malformed contribution can be attributed to the correct participant.

---

### Proof of Concept

**Setup**: 3-of-3 CKD protocol. Participants P1 (honest), P2 (honest), P3 (malicious).

**Attack**:
1. P3 runs a modified client. Instead of calling `compute_signature_share`, it sends `(big_y = G, big_c = G)` to the coordinator.
2. The coordinator receives contributions from P1, P2, P3 and sums them without verification (lines 50–55 of `protocol.rs`).
3. The coordinator outputs `CKDOutput { big_y: honest_sum_y + G, big_c: honest_sum_c + G }`.
4. The application calls `ckd_output.unmask(app_sk)` and obtains `msk * H(pk || app_id) + (1 - app_sk) * G` — a silently incorrect confidential key.
5. No error is raised anywhere in the protocol. All honest parties accept the corrupted output. [1](#0-0) [2](#0-1) [3](#0-2)

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
