### Title
Unvalidated Participant Contributions in CKD Protocol Allow Any Single Malicious Participant to Corrupt the Derived Confidential Key — (File: `src/confidential_key_derivation/protocol.rs`)

---

### Summary

The CKD coordinator blindly sums every participant's `(norm_big_y, norm_big_c)` contribution with no cryptographic validation. A single malicious participant can substitute arbitrary group elements for their correct share, silently biasing the final `CKDOutput` and causing the application (e.g., a TEE) to derive a wrong confidential key — with no error surfaced to honest parties.

---

### Finding Description

The analog vulnerability class is **threshold-state bug**: a participant contributes an unchecked initial value into a shared accumulator, and all honest parties accept the corrupted aggregate as valid output.

In `do_ckd_coordinator` the coordinator collects every participant's output and adds it unconditionally:

```rust
// src/confidential_key_derivation/protocol.rs  lines 50-55
for (_, participant_output) in
    recv_from_others::<CKDOutput>(&chan, waitpoint, &participants, me).await?
{
    norm_big_y += participant_output.big_y();
    norm_big_c += participant_output.big_c();
}
``` [1](#0-0) 

The correct contribution from participant `i` must satisfy:

- `norm_big_Y_i = λ_i · y_i · G`
- `norm_big_C_i = λ_i · (x_i · H(pk ‖ app_id) + y_i · A)`

where `x_i` is the private signing share, `y_i` is a fresh random nonce, and `A` is the application public key. There is no proof-of-correct-formation, no Pedersen commitment binding, and no consistency check against the participant's public key share. The coordinator simply trusts whatever bytes arrive on the channel.

The `compute_signature_share` function that honest participants call is:

```rust
// src/confidential_key_derivation/protocol.rs  lines 148-181
let big_s = hash_point * private_share.to_scalar();   // x_i · H(...)
let big_c = big_s + app_pk * y.0;                     // x_i·H + y_i·A
let norm_big_y = big_y * lambda_i;
let norm_big_c = big_c * lambda_i;
``` [2](#0-1) 

A malicious participant skips `compute_signature_share` entirely and sends any two group elements it chooses.

---

### Impact Explanation

The final `CKDOutput` is:

```
Y = Σ norm_big_Y_i,   C = Σ norm_big_C_i
```

The application recovers the confidential key as `C − x_app · Y`, which should equal `msk · H(pk ‖ app_id)`. If even one participant injects a wrong `(ΔY, ΔC)`, the recovered key is `msk · H(pk ‖ app_id) + (ΔC − x_app · ΔY)` — an attacker-controlled offset. The application silently accepts this wrong key; no error is returned.

**Allowed impact matched:** *High — Corruption of CKD outputs so honest parties accept unusable cryptographic outputs.* [3](#0-2) 

---

### Likelihood Explanation

- The attack requires only one malicious participant out of the full set — no threshold collusion needed.
- The attacker needs no special cryptographic capability: sending two arbitrary `ElementG1` values is trivially achievable by any participant who controls their own process.
- The corruption is silent: `do_ckd_coordinator` returns `Ok(Some(ckd_output))` regardless of whether contributions are well-formed.
- The participant path (`do_ckd_participant`) sends directly to the coordinator with no broadcast or cross-check by other participants. [4](#0-3) 

---

### Recommendation

Each participant must prove that their `(norm_big_Y_i, norm_big_C_i)` is correctly formed relative to their public key share `X_i = x_i · G2`. A standard approach is a **Chaum–Pedersen / sigma-protocol** showing:

```
DLEQ( norm_big_C_i − λ_i · X_i · H(pk‖app_id),  norm_big_Y_i ;  base = A, G )
```

This proves knowledge of `λ_i · y_i` and that the same scalar was used in both components, without revealing `y_i`. The coordinator verifies each proof before accumulating. Alternatively, adopt a verifiable-secret-sharing layer so each participant's contribution can be checked against a public commitment before it enters the sum.

---

### Proof of Concept

```
Setup: 3 participants P1, P2, P3; P3 is malicious.
       Coordinator = P1.

Honest flow:
  P1 computes (Y1, C1) = compute_signature_share(...)
  P2 sends correct (Y2, C2) to P1
  P3 sends (G, G)  ← arbitrary, not derived from x3 or any nonce

Coordinator accumulates:
  Y_total = Y1 + Y2 + G
  C_total = C1 + C2 + G

Application decrypts:
  key = C_total − x_app · Y_total
      = (msk · H(pk‖app_id)) + (G − x_app · G)
      = msk · H(pk‖app_id) + (1 − x_app) · G   ← wrong key, no error raised
```

The application silently receives and uses an incorrect derived key. No `ProtocolError` is returned by `do_ckd_coordinator`. [5](#0-4)

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

**File:** src/confidential_key_derivation/protocol.rs (L165-181)
```rust
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
