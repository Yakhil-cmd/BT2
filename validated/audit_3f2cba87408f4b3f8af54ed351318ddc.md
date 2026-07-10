### Title
Unvalidated Participant Contributions in CKD Protocol Allow Malicious Participant to Corrupt Confidential Key Derivation Output — (File: `src/confidential_key_derivation/protocol.rs`)

---

### Summary

The CKD coordinator blindly sums participant-supplied group elements `(norm_big_y, norm_big_c)` with no proof of correctness attached. This is the direct analog of the external report's pattern: a manipulable, participant-controlled value is consumed without validation in a critical protocol computation. A single malicious participant can send arbitrary group elements, causing the coordinator to output a corrupted `CKDOutput` that honest parties accept as valid.

---

### Finding Description

In `do_ckd_coordinator`, the coordinator collects each participant's `(norm_big_y, norm_big_c)` pair and accumulates them with simple addition:

```rust
for (_, participant_output) in
    recv_from_others::<CKDOutput>(&chan, waitpoint, &participants, me).await?
{
    norm_big_y += participant_output.big_y();
    norm_big_c += participant_output.big_c();
}
let ckd_output = CKDOutput::new(norm_big_y, norm_big_c);
``` [1](#0-0) 

The values being summed are produced by `compute_signature_share`, which computes:

- `norm_big_y = lambda_i * y_i * G`
- `norm_big_c = lambda_i * (x_i * H(pk, app_id) + y_i * app_pk)`

and returns them as raw group elements with **no attached ZK proof**:

```rust
let norm_big_y = big_y * lambda_i;
let norm_big_c = big_c * lambda_i;
Ok((norm_big_y, norm_big_c))
``` [2](#0-1) 

There is no proof that `norm_big_c` was formed using the participant's actual key share `x_i`, nor that `norm_big_y` was formed using the same blinding scalar `y_i` as `norm_big_c`. The coordinator has no mechanism to distinguish a correctly-formed contribution from an arbitrary group element pair.

The correct CKD output satisfies:

```
C - Y * app_sk = msk * H(pk, app_id)
```

If participant `j` sends `(delta_Y, delta_C)` instead of their correct share, the coordinator outputs:

```
Y' = Y_honest + delta_Y
C' = C_honest + delta_C
```

Decryption yields `msk * H(pk, app_id) + (delta_C - delta_Y * app_sk)`, which is wrong for any `(delta_Y, delta_C)` not satisfying `delta_C = delta_Y * app_sk` — a relation the attacker cannot satisfy without knowing `app_sk`.

---

### Impact Explanation

**High — Corruption of CKD outputs so honest parties accept unusable cryptographic outputs.**

The coordinator outputs a `CKDOutput` that is structurally well-formed but cryptographically incorrect. The downstream application will unmask it and receive a wrong confidential derived key. Because the coordinator performs no verification before returning `Some(ckd_output)`, all honest parties that trust the coordinator's output will accept the corrupted result. The confidential derived key is permanently wrong for that protocol run; there is no recovery without re-running the protocol with the malicious participant excluded.

---

### Likelihood Explanation

Any participant in the CKD protocol can trigger this. The entry path is the standard `ckd()` public API: [3](#0-2) 

The attacker needs only to be listed in `participants` and to send a malformed `CKDOutput` over the channel instead of the honest computation. No special privilege, leaked key, or cryptographic break is required. The `recv_from_others` call accepts any well-deserializable `CKDOutput` from any participant: [4](#0-3) 

---

### Recommendation

Attach a **dlog-equality (Chaum–Pedersen) proof** to each participant's contribution, proving that the same discrete-log witness `y_i` was used in both `norm_big_y = lambda_i * y_i * G` and the `y_i * app_pk` term inside `norm_big_c`, and that `norm_big_c` encodes the correct key share `x_i`. The existing `dlogeq.rs` proof infrastructure in `src/crypto/proofs/dlogeq.rs` is available for this purpose. The coordinator must verify each proof before accumulating the contribution.

---

### Proof of Concept

1. All `N` participants call `ckd(...)` with the same `(participants, coordinator, app_id, app_pk)`.
2. Malicious participant `j` intercepts the channel and, instead of sending the output of `compute_signature_share`, sends `(delta_Y, delta_C)` where `delta_Y` and `delta_C` are arbitrary non-identity group elements chosen by the attacker.
3. The coordinator's loop at line 50–55 adds `delta_Y` and `delta_C` into the running sums without any check.
4. `CKDOutput::new(norm_big_y, norm_big_c)` is returned as `Some(...)` — the coordinator signals success.
5. The application calls `ckd_output.unmask(app_sk)` and receives `msk * H(pk, app_id) + (delta_C - delta_Y * app_sk)` — a wrong key — with no indication of failure.

### Citations

**File:** src/confidential_key_derivation/protocol.rs (L50-57)
```rust
    for (_, participant_output) in
        recv_from_others::<CKDOutput>(&chan, waitpoint, &participants, me).await?
    {
        norm_big_y += participant_output.big_y();
        norm_big_c += participant_output.big_c();
    }
    let ckd_output = CKDOutput::new(norm_big_y, norm_big_c);
    Ok(Some(ckd_output))
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

**File:** src/confidential_key_derivation/protocol.rs (L179-181)
```rust
    let norm_big_y = big_y * lambda_i;
    let norm_big_c = big_c * lambda_i;
    Ok((norm_big_y, norm_big_c))
```
