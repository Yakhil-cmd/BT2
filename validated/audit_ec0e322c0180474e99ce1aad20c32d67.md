### Title
Unvalidated `app_pk` in CKD Protocol Allows Malicious Participant to Silently Corrupt CKD Output - (File: src/confidential_key_derivation/protocol.rs)

---

### Summary

The `ckd()` function accepts an `app_pk` (application public key) from each participant independently with no in-protocol consensus validation. A malicious participant can supply a different `app_pk` than the one used by honest parties, silently corrupting the aggregated `CKDOutput`. The coordinator and all honest participants have no mechanism to detect this corruption and will accept an unusable cryptographic output.

---

### Finding Description

In `src/confidential_key_derivation/protocol.rs`, the public entry point `ckd()` accepts `app_pk: PublicKey` as a caller-supplied parameter:

```rust
pub fn ckd(
    participants: &[Participant],
    coordinator: Participant,
    me: Participant,
    key_pair: KeygenOutput,
    app_id: impl Into<AppId>,
    app_pk: PublicKey,          // ← caller-controlled, no consensus check
    rng: impl CryptoRngCore + Send + 'static,
) -> Result<impl Protocol<Output = CKDOutputOption>, InitializationError>
```

The function validates that `me` and `coordinator` are members of the participant list (lines 88–101), but performs **no validation of `app_pk`** and establishes **no in-protocol consensus** that all participants are using the same value.

`app_pk` is then forwarded into `compute_signature_share()` (line 174), where it is used directly in a computation involving the participant's private signing share:

```rust
// S <- x_i . H(app_id)
let big_s = hash_point * private_share.to_scalar();

// C <- S + y . A          ← app_pk (A) is attacker-controlled
let big_c = big_s + app_pk * y.0;
```

The Lagrange-weighted pair `(norm_big_y, norm_big_c)` is then sent to the coordinator via `do_ckd_participant()` (line 30). The coordinator in `do_ckd_coordinator()` (lines 50–55) blindly sums every received contribution:

```rust
for (_, participant_output) in
    recv_from_others::<CKDOutput>(&chan, waitpoint, &participants, me).await?
{
    norm_big_y += participant_output.big_y();
    norm_big_c += participant_output.big_c();
}
```

There is no step where participants broadcast their `app_pk` for cross-verification, no transcript binding of `app_pk`, and no post-aggregation check. The resulting `CKDOutput` is returned to all honest parties as authoritative.

This is the direct analog of the reported vulnerability: just as the Controller called an arbitrary address supplied by the user without checking `isQToken`, the CKD protocol uses an arbitrary `app_pk` supplied by each participant without checking that it matches the value every other participant is using.

---

### Impact Explanation

A malicious participant who supplies `app_pk_malicious ≠ app_pk_correct` causes the aggregated output to be:

```
C_total = λ_malicious · (x_malicious · H + y_malicious · app_pk_malicious)
        + Σ_{i ≠ malicious} λ_i · (x_i · H + y_i · app_pk_correct)
```

This value does not equal `(Σ λ_i · x_i) · H + (Σ λ_i · y_i) · app_pk_correct`, so `CKDOutput.unmask(app_sk)` will produce a wrong group element — not the intended derived key. Honest parties have no way to detect this without the application secret key, so they accept a silently corrupted, unusable CKD output.

**Matched impact:** *High — Corruption of CKD outputs so honest parties accept unusable cryptographic outputs.*

---

### Likelihood Explanation

Any single malicious participant can trigger this with zero special knowledge: they simply pass a different `app_pk` (e.g., the group identity, a random point, or a crafted point) when invoking `ckd()`. No cryptographic capability is required. The attack is completely silent — the coordinator cannot attribute the corruption to any specific participant, and no error is returned.

---

### Recommendation

Bind `app_pk` into the protocol's session transcript so that all participants must agree on the same value before any private computation occurs. Concretely:

1. **Broadcast `app_pk`** in an early round (analogous to how `sid_i` is broadcast in DKG) and abort if any participant's value differs.
2. **Include `app_pk` in the session-ID hash** so that participants using different values operate in cryptographically distinct sessions and their contributions cannot be mixed.
3. **Validate `app_pk` is a non-identity curve point** before use, to prevent degenerate inputs.

The mitigation mirrors the one recommended in the external report: just as the fix was to probe `isQToken(_qToken)` before calling the address, the fix here is to verify `app_pk` consensus before using it in share computation.

---

### Proof of Concept

1. Honest participants call `ckd(..., app_pk = app_sk * G, ...)`.
2. Malicious participant calls `ckd(..., app_pk = G1::identity(), ...)` (zero element).
3. Malicious participant computes `big_c_malicious = x_malicious · H + 0 = x_malicious · H`.
4. Coordinator receives `norm_big_c_malicious = λ_malicious · x_malicious · H`.
5. Coordinator sums: `C_total = λ_malicious · x_malicious · H + Σ_{honest} λ_i · (x_i · H + y_i · app_pk)`.
6. `C_total` does not equal the intended `(Σ λ_i · x_i) · H + (Σ λ_i · y_i) · app_pk`.
7. `ckd_output.unmask(app_sk)` returns a wrong group element; honest parties accept it with no error. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3)

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

**File:** src/confidential_key_derivation/protocol.rs (L66-101)
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
    // not enough participants
    if participants.len() < 2 {
        return Err(InitializationError::NotEnoughParticipants {
            participants: participants.len(),
        });
    }

    // kick out duplicates
    let Some(participants) = ParticipantList::new(participants) else {
        return Err(InitializationError::DuplicateParticipants);
    };

    // ensure my presence in the participant list
    if !participants.contains(me) {
        return Err(InitializationError::MissingParticipant {
            role: "self",
            participant: me,
        });
    }

    // ensure the coordinator is a participant
    if !participants.contains(coordinator) {
        return Err(InitializationError::MissingParticipant {
            role: "coordinator",
            participant: coordinator,
        });
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
