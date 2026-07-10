### Title
Malicious Participant Can Corrupt CKD Output Without Detection via Unvalidated Contribution Shares - (File: src/confidential_key_derivation/protocol.rs)

### Summary
The CKD coordinator accepts `CKDOutput` contributions from participants without any cryptographic proof that each contribution was computed correctly from the participant's actual key share. A single malicious participant can send arbitrary `(big_y, big_c)` values, silently corrupting the final derived confidential key. Honest parties have no mechanism to detect this corruption.

### Finding Description

The `do_ckd_coordinator` function collects per-participant contributions and sums them to produce the final CKD output: [1](#0-0) 

Each participant is expected to compute their contribution as:
- `big_y_i = lambda_i * (y_i * G)` — a blinding commitment
- `big_c_i = lambda_i * (x_i * H(pk || app_id) + y_i * app_pk)` — the ElGamal-encrypted secret share contribution [2](#0-1) 

The coordinator receives these values via `recv_from_others` and unconditionally adds them: [3](#0-2) 

There is no zero-knowledge proof, commitment-and-reveal, or any other cryptographic check that `big_c_i` was formed using the participant's actual signing share `x_i`. The `recv_from_others` helper only enforces that exactly one message per known participant is received — it does not validate message content: [4](#0-3) 

The `Protocol::message(from, data)` API, which feeds into `recv_from_others`, accepts the `from` field as a caller-supplied parameter with no cryptographic binding to the message content: [5](#0-4) 

### Impact Explanation

A malicious participant sends an arbitrary `(big_y_i, big_c_i)` pair — for example, `big_c_i = 0` or a value encoding a chosen secret — instead of the correctly computed contribution. The coordinator sums all contributions including the malicious one, producing a `CKDOutput` that does not encode `msk * H(pk || app_id)`. The app holder who calls `unmask(app_sk)` on this output receives a wrong confidential key with no indication of failure, since there is no post-protocol verification step. This matches: **High: Corruption of CKD outputs so honest parties accept unusable cryptographic outputs.**

### Likelihood Explanation

Any single participant in the CKD protocol can mount this attack. No special privilege is required beyond being an enrolled participant. The attacker simply deviates from the protocol in `do_ckd_participant` by sending a crafted `(big_y, big_c)` tuple to the coordinator. The attack is silent — the protocol completes normally and returns `Some(ckd_output)` to the coordinator with no error. [6](#0-5) 

### Recommendation

Require each participant to accompany their `(big_y_i, big_c_i)` contribution with a zero-knowledge proof of correct formation — specifically, a proof of knowledge of `(x_i, y_i)` such that `big_c_i = x_i * H(pk || app_id) + y_i * app_pk` and `big_y_i = y_i * G`, where `x_i` is consistent with the participant's public verification share. The coordinator must verify all proofs before summing contributions. Alternatively, use a commitment-and-reveal scheme so that deviations are attributable and detectable.

### Proof of Concept

1. Honest participants run `ckd(participants, coordinator, me, key_pair, app_id, app_pk, rng)`.
2. The malicious participant's `do_ckd_participant` sends `(ElementG1::identity(), ElementG1::identity())` instead of the correctly computed share to the coordinator.
3. The coordinator's `do_ckd_coordinator` sums all contributions including `(0, 0)`, producing `(sum_y - lambda_malicious * big_y_malicious, sum_c - lambda_malicious * big_c_malicious)` — a value that does not decrypt to `msk * H(pk || app_id)`.
4. The coordinator returns `Some(ckd_output)` with no error. The app holder calls `ckd_output.unmask(app_sk)` and receives a wrong key, silently accepting a corrupted CKD result. [7](#0-6)

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

**File:** src/protocol/internal.rs (L512-514)
```rust
    fn message(&mut self, from: Participant, data: MessageData) {
        self.comms.push_message(from, data);
    }
```
