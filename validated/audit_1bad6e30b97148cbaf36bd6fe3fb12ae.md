Looking at the CKD protocol in `src/confidential_key_derivation/protocol.rs`, I can identify a valid analog.

---

### Title
Malicious CKD Participant Can Corrupt Derived Key Output Without Detection — (`File: src/confidential_key_derivation/protocol.rs`)

### Summary
The CKD coordinator blindly aggregates participant contributions (`big_y`, `big_c`) with no cryptographic verification that each contribution was honestly computed from the participant's actual key share. A single malicious participant can send arbitrary group elements, silently corrupting the final `CKDOutput` and causing the coordinator to derive an incorrect confidential key.

### Finding Description
In `do_ckd_coordinator` (`src/confidential_key_derivation/protocol.rs`, lines 50–57), the coordinator receives a `CKDOutput` from every other participant and unconditionally adds each contribution into the running sum:

```rust
for (_, participant_output) in
    recv_from_others::<CKDOutput>(&chan, waitpoint, &participants, me).await?
{
    norm_big_y += participant_output.big_y();
    norm_big_c += participant_output.big_c();
}
let ckd_output = CKDOutput::new(norm_big_y, norm_big_c);
```

Each participant is supposed to compute:
- `norm_big_y = λ_i · y_i · G`
- `norm_big_c = λ_i · (x_i · H(pk ‖ app_id) + y_i · app_pk)`

where `x_i` is their private signing share and `y_i` is a fresh random scalar. No zero-knowledge proof, commitment, or consistency check accompanies these values. The coordinator cannot verify correctness because:
1. `y_i` is known only to the participant, so `norm_big_y` cannot be independently recomputed.
2. Verifying `norm_big_c` requires `app_sk` (the application secret key), which the coordinator does not possess.

The non-coordinator path (`do_ckd_participant`, lines 17–33) simply sends the two group elements privately to the coordinator and returns `None`, with no broadcast or accountability mechanism.

### Impact Explanation
A malicious participant sends arbitrary `ElementG1` values for `big_y` and `big_c`. The coordinator sums them into the final `CKDOutput`. The resulting output does not equal `(Σ λ_i y_i G, msk · H(pk, app_id) + Y · app_sk)`, so `CKDOutput::unmask(app_sk)` yields an incorrect group element instead of the intended confidential derived key. The coordinator has no in-protocol signal that the output is wrong; they accept and propagate a cryptographically useless result. This matches the allowed impact: **High — Corruption of CKD outputs so honest parties accept unusable cryptographic outputs**.

### Likelihood Explanation
Any participant enrolled in a CKD session can trigger this with zero special privileges. The attack requires only that the participant deviate from the protocol when computing and sending their `(norm_big_y, norm_big_c)` pair. No leaked keys, no external oracle, and no cryptographic break are needed. The malicious participant is indistinguishable from an honest one because there is no accountability mechanism.

### Recommendation
Add a zero-knowledge proof of correct contribution alongside each `(norm_big_y, norm_big_c)` pair. Concretely, each participant should prove in zero knowledge that:
- `norm_big_y` is a scalar multiple of `G` for some `λ_i · y_i` they know, and
- `norm_big_c = norm_big_y · (app_sk / y_i) + λ_i · x_i · H(pk ‖ app_id)` — equivalently, a proof of the Diffie-Hellman relation between `norm_big_y`, `app_pk`, and the `x_i`-dependent term.

A standard sigma protocol (e.g., a Chaum-Pedersen proof) over the BLS12-381 G1 group can achieve this without revealing `x_i` or `y_i`. Alternatively, use a verifiable secret sharing or commitment-then-reveal scheme so the coordinator can reject malformed contributions before aggregating.

### Proof of Concept

**Setup**: 3 participants `[P0, P1, P2]`; `P1` is coordinator; `P2` is malicious.

**Honest execution** (expected):
```
P0 → P1: (λ_0·y_0·G,  λ_0·(x_0·H + y_0·app_pk))
P2 → P1: (λ_2·y_2·G,  λ_2·(x_2·H + y_2·app_pk))   ← honest
Coordinator P1 aggregates → correct CKDOutput
unmask(app_sk) == msk · H(pk, app_id)  ✓
```

**Malicious execution**:
```rust
// P2 sends zeroed-out or random group elements instead of honest values
chan.send_private(waitpoint, coordinator, &(ElementG1::identity(), ElementG1::identity()))?;
```
```
P0 → P1: (λ_0·y_0·G,  λ_0·(x_0·H + y_0·app_pk))
P2 → P1: (identity,   identity)                     ← malicious
Coordinator P1 aggregates → corrupted CKDOutput
unmask(app_sk) ≠ msk · H(pk, app_id)  ✗
```

The coordinator receives `Ok(Some(corrupted_ckd_output))` with no error, no warning, and no way to detect the corruption. The derived confidential key is permanently wrong for this session. [1](#0-0) [2](#0-1) [3](#0-2)

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
