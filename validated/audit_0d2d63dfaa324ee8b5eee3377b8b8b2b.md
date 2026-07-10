### Title
Malicious Participant Can Corrupt CKD Output Without Detection — (`src/confidential_key_derivation/protocol.rs`)

### Summary
The `do_ckd_coordinator` function aggregates participant-supplied `CKDOutput` shares (`big_y`, `big_c`) into the final confidential key derivation result without performing any verification that each participant's contribution was honestly computed. A single malicious participant can send arbitrary elliptic-curve points in place of their legitimate share, causing the coordinator to produce and return a silently corrupted `CKDOutput` that all honest parties accept as valid.

### Finding Description

**Root cause — missing proof of correct computation**

In `src/confidential_key_derivation/protocol.rs`, `do_ckd_coordinator` collects each participant's `(norm_big_y, norm_big_c)` pair and unconditionally adds them to the running aggregate:

```rust
// src/confidential_key_derivation/protocol.rs  lines 50-55
for (_, participant_output) in
    recv_from_others::<CKDOutput>(&chan, waitpoint, &participants, me).await?
{
    norm_big_y += participant_output.big_y();
    norm_big_c += participant_output.big_c();
}
``` [1](#0-0) 

No check is performed to confirm that the received `big_y` and `big_c` are consistent with the participant's committed public key share or with the protocol's `hash_point`. The coordinator then immediately wraps the raw aggregate into the final output:

```rust
let ckd_output = CKDOutput::new(norm_big_y, norm_big_c);
Ok(Some(ckd_output))
``` [2](#0-1) 

**What an honest participant computes**

`compute_signature_share` produces:
- `big_y = y * G` (random blinding)
- `big_c = x_i * H(pk ‖ app_id) + y * app_pk` (ElGamal encryption of the secret share)
- Both scaled by the Lagrange coefficient `λ_i` [3](#0-2) 

The correctness invariant is: `big_c_i` must equal `λ_i * (x_i * hash_point + y_i * app_pk)`. There is no zero-knowledge proof, commitment, or consistency check enforcing this invariant on the coordinator side.

**Exploit path**

1. A malicious participant `P_m` participates in a legitimate CKD session.
2. Instead of calling `compute_signature_share` honestly, `P_m` sends an arbitrary pair `(big_y', big_c')` to the coordinator via the private channel.
3. The coordinator's loop adds `big_y'` and `big_c'` to the aggregate without any validation.
4. The resulting `CKDOutput` is `(Σ λ_i y_i G + big_y', Σ λ_i (x_i H + y_i A) + big_c')`.
5. When the application calls `unmask(app_sk)`, it computes `big_c_total - app_sk * big_y_total`, which equals `msk * H(pk, app_id) + (big_c' - app_sk * big_y')` — a value that is wrong by an attacker-controlled additive offset.
6. The coordinator and all honest participants have no mechanism to detect the corruption; the protocol returns `Ok(Some(ckd_output))` with no error.

### Impact Explanation

A single malicious participant (no special privilege required beyond being a listed participant) can silently corrupt the CKD output accepted by the coordinator. The derived confidential key `msk * H(pk, app_id)` is replaced by an attacker-shifted value. Any downstream consumer of the CKD output (e.g., a TEE decrypting a secret) will silently receive the wrong key. This maps directly to: **High — Corruption of CKD outputs so honest parties accept unusable or inconsistent cryptographic outputs.**

### Likelihood Explanation

Any participant in the CKD protocol can mount this attack with zero cryptographic capability — they simply send two arbitrary group elements instead of their honest contribution. The attack requires no leaked keys, no side channels, and no external assumptions. It is reachable by any unprivileged library caller who is listed as a participant.

### Recommendation

Require each participant to accompany their `(norm_big_y, norm_big_c)` with a zero-knowledge proof of correct computation — specifically, a proof that `big_c_i` is a valid ElGamal encryption of `λ_i * x_i * H(pk ‖ app_id)` under `app_pk`, consistent with the participant's public key share `λ_i * x_i * G2`. A Chaum-Pedersen-style DLEQ proof over the BLS12-381 G1 curve is the standard approach. The coordinator must verify all proofs before aggregating contributions and abort if any proof fails.

### Proof of Concept

```
Setup: 3 participants, threshold = 3, coordinator = P0.
Honest run: each P_i sends (λ_i * y_i * G, λ_i * (x_i * H + y_i * A)).
Malicious run: P_1 sends (G, G) instead of its honest share.

Coordinator aggregates:
  big_y_total = λ_0*y_0*G + G + λ_2*y_2*G          ← corrupted
  big_c_total = λ_0*(x_0*H+y_0*A) + G + λ_2*(x_2*H+y_2*A)  ← corrupted

unmask(app_sk) = big_c_total - app_sk * big_y_total
              = msk*H + G - app_sk*G
              = msk*H + (1 - app_sk)*G   ← wrong, not msk*H

No error is returned. The coordinator returns Ok(Some(corrupted_ckd_output)).
```

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
