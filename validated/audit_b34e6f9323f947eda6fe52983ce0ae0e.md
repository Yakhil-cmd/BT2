### Title
Unverified Participant Contributions in CKD Protocol Allow Malicious Participant to Corrupt Derived Confidential Key - (File: `src/confidential_key_derivation/protocol.rs`)

---

### Summary
The `do_ckd_coordinator` function aggregates `(norm_big_y, norm_big_c)` contributions from all participants without any cryptographic verification that each contribution was honestly computed from the participant's actual key share. A single malicious participant can inject arbitrary group elements, causing the coordinator to accumulate a corrupted `CKDOutput` and derive an incorrect confidential key.

---

### Finding Description

In `src/confidential_key_derivation/protocol.rs`, the coordinator path of the CKD protocol is:

```rust
async fn do_ckd_coordinator(...) -> Result<CKDOutputOption, ProtocolError> {
    let (mut norm_big_y, mut norm_big_c) =
        compute_signature_share(&participants, me, key_pair, app_id, app_pk, rng)?;

    let waitpoint = chan.next_waitpoint();

    for (_, participant_output) in
        recv_from_others::<CKDOutput>(&chan, waitpoint, &participants, me).await?
    {
        norm_big_y += participant_output.big_y();   // ← no verification
        norm_big_c += participant_output.big_c();   // ← no verification
    }
    let ckd_output = CKDOutput::new(norm_big_y, norm_big_c);
    Ok(Some(ckd_output))
}
``` [1](#0-0) 

Each honest participant is supposed to compute and send:

- `norm_big_y = lambda_i * y_i * G₁`
- `norm_big_c = lambda_i * (x_i * H(pk, app_id) + y_i * app_pk)`

where `x_i` is their private key share and `y_i` is a fresh random scalar. [2](#0-1) 

The coordinator blindly accumulates whatever group elements it receives. There is no zero-knowledge proof, commitment binding, or any other mechanism to verify that a participant's `(norm_big_y, norm_big_c)` was honestly derived from their registered key share. The participant path simply sends and returns:

```rust
fn do_ckd_participant(...) -> Result<CKDOutputOption, ProtocolError> {
    let (norm_big_y, norm_big_c) =
        compute_signature_share(participants, me, key_pair, app_id, app_pk, rng)?;
    let waitpoint = chan.next_waitpoint();
    chan.send_private(waitpoint, coordinator, &(norm_big_y, norm_big_c))?;
    Ok(None)
}
``` [3](#0-2) 

This is structurally identical to the `LibTransfer` bug: the code assumes the received value equals the expected value and updates its internal accumulator accordingly, without measuring what was actually received.

---

### Impact Explanation

The final `CKDOutput` is `(Y, C)` where the correct values satisfy:

```
Y = Σ lambda_i * y_i * G₁
C = Σ lambda_i * (x_i * H(pk, app_id) + y_i * app_pk)
```

The `unmask` operation recovers the confidential key as `C - app_sk * Y = msk * H(pk, app_id)`.

If a malicious participant substitutes arbitrary elements `(Y', C')` for their honest contribution, the accumulated `(Y, C)` is shifted by `(Y' - Y_honest, C' - C_honest)`. The coordinator's `unmask` then yields a value that is not `msk * H(pk, app_id)`, i.e., the derived confidential key is silently wrong. The coordinator has no way to detect this.

**Impact: High** — Corruption of CKD output so honest parties accept an incorrect derived confidential key, matching the allowed impact: *"Corruption of DKG, reshare, refresh, presign, sign, or CKD outputs so honest parties accept inconsistent public keys, participant sets, transcripts, or unusable cryptographic outputs."*

---

### Likelihood Explanation

Any registered participant in the CKD protocol can trigger this. No special privilege beyond protocol membership is required. The attacker simply sends a crafted `CKDOutput` message to the coordinator instead of their honest contribution. The coordinator has no defense.

**Likelihood: Medium** — Requires a malicious insider participant, which is a realistic threat in a threshold setting.

---

### Recommendation

Each participant should accompany their `(norm_big_y, norm_big_c)` with a zero-knowledge proof of correct computation — specifically, a proof of knowledge of `(y_i, x_i)` such that:

- `norm_big_y = lambda_i * y_i * G₁`
- `norm_big_c = lambda_i * (x_i * H(pk, app_id) + y_i * app_pk)`

and that `x_i` is consistent with the participant's registered public key share `X_i = x_i * G₂`. The coordinator must verify each proof before accumulating the contribution, analogous to how the fixed `receiveToken` measures the actual balance delta rather than trusting the caller-supplied amount.

---

### Proof of Concept

1. Honest participants P₁, P₂, P₃ run the CKD protocol with coordinator P₁.
2. Malicious participant P₂ intercepts the `do_ckd_participant` path and instead of calling `compute_signature_share`, sends `(G₁, G₁)` (the generator point) as its `CKDOutput`.
3. The coordinator at line 53–54 adds `G₁` to both `norm_big_y` and `norm_big_c` without any check.
4. The final `CKDOutput` is `(Y_honest + G₁, C_honest + G₁)`.
5. `unmask(app_sk)` computes `(C_honest + G₁) - app_sk * (Y_honest + G₁) = msk * H(pk, app_id) + G₁ - app_sk * G₁`, which is not the correct confidential key.
6. The coordinator silently accepts and returns this corrupted value with no error. [4](#0-3)

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
