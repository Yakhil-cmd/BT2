### Title
Unverified `app_pk` Parameter in CKD Protocol Allows Malicious Participant to Corrupt Derivation Output — (File: `src/confidential_key_derivation/protocol.rs`)

---

### Summary
The CKD protocol accepts `app_pk` (the client's blinding public key) as a caller-supplied parameter with no cryptographic binding to the session. A malicious participant can substitute an arbitrary `app_pk'` when invoking `ckd()`, silently corrupting the aggregated `CKDOutput` and causing honest parties to accept an unusable derived key.

---

### Finding Description

In `src/confidential_key_derivation/protocol.rs`, the public entry point `ckd()` accepts `app_pk: PublicKey` as a raw caller-supplied argument: [1](#0-0) 

Each participant independently invokes `ckd()` with their own `app_pk`. Inside `compute_signature_share()`, `app_pk` is used directly in the blinding computation: [2](#0-1) 

Specifically, the line `let big_c = big_s + app_pk * y.0;` at line 174 uses the caller-supplied `app_pk` without any verification. The coordinator in `do_ckd_coordinator()` then aggregates all partial `(norm_big_y, norm_big_c)` contributions: [3](#0-2) 

There is **no broadcast, commitment, or consistency check** that binds `app_pk` to the session. No participant is required to prove they used the same `app_pk` as the coordinator. The session has no identifier that includes `app_pk`, making this a direct analog to the `startSqrtPriceX96` class: a protocol-critical parameter is caller-controlled and excluded from the session binding.

---

### Impact Explanation

A malicious participant using `app_pk' ≠ app_pk` computes:

```
C_i' = S_i + y_i * app_pk'
```

instead of the honest:

```
C_i = S_i + y_i * app_pk
```

The coordinator aggregates all contributions, producing a corrupted output:

```
big_c = msk · H(pk, app_id) + y · app_pk + y_malicious · (app_pk' − app_pk)
```

When the client unmasks with `s = big_c − app_sk · big_y`:

```
s = msk · H(pk, app_id) + y_malicious · (app_pk' − app_pk)
```

This is not the expected `msk · H(pk, app_id)`. The derived confidential key is incorrect and unusable. This matches the **High** impact: *Corruption of CKD outputs so honest parties accept unusable cryptographic outputs.*

---

### Likelihood Explanation

A malicious participant can trivially substitute any `app_pk'` — including the identity element `G1::identity()` or the generator `G` — when calling `ckd()`. No special cryptographic knowledge is required. The coordinator has no mechanism to detect the substitution because there is no cross-participant consistency check on `app_pk` anywhere in the protocol flow. [4](#0-3) 

The participant sends only `(norm_big_y, norm_big_c)` to the coordinator — the `app_pk` used to produce them is never transmitted or verified.

---

### Recommendation

Bind `app_pk` to the session by including it in a session identifier, or add a commitment round where participants commit to their `app_pk` before revealing partial outputs. At minimum, the coordinator should broadcast `app_pk` to all participants and require them to echo it back before computing their contribution, so any deviation is detectable.

---

### Proof of Concept

1. Coordinator initiates a CKD session with `app_pk = A = app_sk · G`.
2. Malicious participant calls `ckd()` with `app_pk' = G1::identity()` (the identity element).
3. Malicious participant computes `C_i' = S_i + y_i · 0 = S_i = hash_point · private_share_i`.
4. Coordinator aggregates: `big_c = (honest C_i contributions) + S_malicious`.
5. Client unmasks: `s = big_c − app_sk · big_y = msk · H(pk, app_id) − y_malicious · A`.
6. Client receives an incorrect, unusable derived key with no indication of which participant was malicious. [5](#0-4) [6](#0-5)

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

**File:** src/confidential_key_derivation/protocol.rs (L66-74)
```rust
pub fn ckd(
    participants: &[Participant],
    coordinator: Participant,
    me: Participant,
    key_pair: KeygenOutput,
    app_id: impl Into<AppId>,
    app_pk: PublicKey,
    rng: impl CryptoRngCore + Send + 'static,
) -> Result<impl Protocol<Output = CKDOutputOption>, InitializationError> {
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

**File:** src/confidential_key_derivation/mod.rs (L67-71)
```rust
pub fn hash_app_id_with_pk(pk: &VerifyingKey, app_id: &[u8]) -> ElementG1 {
    let compressed_pk = pk.to_element().to_compressed();
    let input = [compressed_pk.as_slice(), app_id].concat();
    ciphersuite::hash_to_curve(&input)
}
```
