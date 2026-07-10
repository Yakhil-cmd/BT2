### Title
Unverified Participant Contributions in CKD Coordinator Allow Confidential Key Corruption — (`src/confidential_key_derivation/protocol.rs`)

---

### Summary

In `do_ckd_coordinator`, the coordinator collects `CKDOutput` contributions from all participants and accumulates them into the final output without any verification that each contribution is cryptographically consistent with the sender's public key share. A malicious participant can send arbitrary group elements; the coordinator adds them unconditionally, silently corrupting the derived confidential key. This is the direct analog of the external report: a sub-operation returns a value that is stored and used, but the required invariant on that value is never checked before the protocol concludes.

---

### Finding Description

`do_ckd_coordinator` in `src/confidential_key_derivation/protocol.rs` is responsible for aggregating per-participant CKD shares into the final `CKDOutput`:

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

    let waitpoint = chan.next_waitpoint();

    for (_, participant_output) in
        recv_from_others::<CKDOutput>(&chan, waitpoint, &participants, me).await?
    {
        norm_big_y += participant_output.big_y();   // ← no check
        norm_big_c += participant_output.big_c();   // ← no check
    }
    let ckd_output = CKDOutput::new(norm_big_y, norm_big_c);
    Ok(Some(ckd_output))
}
``` [1](#0-0) 

Each honest participant is supposed to send `(λ_i · y_i · G₁, λ_i · (x_i · H(pk, app_id) + y_i · app_pk))`. The coordinator can verify this relationship using a pairing check against the participant's public key share `X_i = x_i · G₂`:

```
e(norm_big_c − norm_big_y · app_pk, G₂) == e(H(pk, app_id), λ_i · X_i)
```

No such check is performed. The coordinator simply accumulates whatever group elements arrive from the network.

The per-participant contribution is computed honestly in `compute_signature_share`: [2](#0-1) 

But the coordinator never validates that what it *receives* matches what an honest execution of that function would have produced.

The parallel to the external report is exact:

| External report | This codebase |
|---|---|
| `liquidityAdded` returned by `increaseLiquidity()` | `participant_output` returned by `recv_from_others` |
| Never checked against `lien.liquidity` | Never verified against participant's public key share |
| Lien closed with LP potentially under-repaid | CKD output produced with corrupted aggregate |

---

### Impact Explanation

The final `CKDOutput` `(Y, C)` satisfies `C = msk · H(pk, app_id) + Y · app_pk` only when all contributions are honest. If a malicious participant injects an arbitrary `(Δ_Y, Δ_C)`, the coordinator computes:

```
Y'  = Y  + Δ_Y
C'  = C  + Δ_C
```

The application unmasks via `C' − app_sk · Y' = msk · H(pk, app_id) + (Δ_C − app_sk · Δ_Y)`, which is an attacker-controlled deviation from the correct confidential key. The honest coordinator and all honest participants accept this corrupted output as valid and return it to the caller with no error.

This maps directly to: **High — Corruption of CKD outputs so honest parties accept unusable cryptographic outputs.**

---

### Likelihood Explanation

Any single participant in the CKD session is a sufficient attacker. The participant controls the `KeygenOutput` they supply (including a wrong `private_share`) or, since the protocol runs over an abstract `SharedChannel`, can inject arbitrary bytes at the network layer. No special privilege beyond being a listed participant is required. The attack is silent — the coordinator returns `Ok(Some(ckd_output))` with no indication of corruption.

---

### Recommendation

Add a pairing-based consistency check on each received contribution before accumulating it:

```rust
for (from, participant_output) in
    recv_from_others::<CKDOutput>(&chan, waitpoint, &participants, me).await?
{
    // Verify: e(big_c - big_y * app_pk, G2) == e(H(pk, app_id), lambda_i * X_i)
    let lhs = participant_output.big_c() - app_pk * participant_output.big_y();
    let lambda_i = participants.lagrange::<BLS12381SHA256>(from)?;
    let x_i_pub = /* participant from's public key share on G2 */;
    let rhs_base = hash_app_id_with_pk(&key_pair.public_key, &app_id);
    if pairing(lhs, G2::generator()) != pairing(rhs_base, lambda_i * x_i_pub) {
        return Err(ProtocolError::MaliciousParticipant(from));
    }
    norm_big_y += participant_output.big_y();
    norm_big_c += participant_output.big_c();
}
```

This requires `KeygenOutput` (or a separate public key package) to expose individual participant verifying shares on G2, which should be stored during DKG.

---

### Proof of Concept

1. Honest participants run DKG to produce key shares with master secret key `msk`.
2. Attacker (participant `P_evil`) participates in a CKD session.
3. Instead of sending the correct `(norm_big_y, norm_big_c)`, `P_evil` sends `(Δ_Y, Δ_C)` for arbitrary non-zero `Δ_Y, Δ_C ∈ G₁`.
4. The coordinator's loop at lines 50–55 adds `Δ_Y` and `Δ_C` unconditionally.
5. The returned `CKDOutput` satisfies `C' − app_sk · Y' = msk · H(pk, app_id) + (Δ_C − app_sk · Δ_Y)`.
6. The TEE application unmasks to a wrong key with no error raised anywhere in the protocol. [3](#0-2)

### Citations

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
