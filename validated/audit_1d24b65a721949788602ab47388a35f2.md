### Title
Malicious Participant Can Corrupt CKD Output via Unvalidated Contributions - (File: `src/confidential_key_derivation/protocol.rs`)

### Summary
The `do_ckd_coordinator` function accumulates `(big_y, big_c)` group-element contributions from each participant into the final CKD output without any proof of correctness or consistency check. A single malicious participant can send arbitrary group elements, causing the coordinator to output a corrupted `CKDOutput`. Any honest party that subsequently uses this output to unmask the confidential key will derive a wrong value, permanently breaking the CKD result for that invocation.

### Finding Description

**Root cause — state accumulated from unvalidated external input:**

In `do_ckd_coordinator`, the coordinator waits for every other participant's `CKDOutput` and blindly adds each received `big_y` and `big_c` into the running sum:

```rust
// src/confidential_key_derivation/protocol.rs  lines 50-56
for (_, participant_output) in
    recv_from_others::<CKDOutput>(&chan, waitpoint, &participants, me).await?
{
    norm_big_y += participant_output.big_y();
    norm_big_c += participant_output.big_c();
}
let ckd_output = CKDOutput::new(norm_big_y, norm_big_c);
Ok(Some(ckd_output))
``` [1](#0-0) 

The honest computation each participant is supposed to perform is:

```
big_y  = lambda_i * y_i * G
big_c  = lambda_i * (x_i * H(pk, app_id) + y_i * app_pk)
```

as implemented in `compute_signature_share`: [2](#0-1) 

However, the coordinator performs **no verification** that the received `(big_y, big_c)` pair satisfies this relation. There is no zero-knowledge proof, no commitment binding `big_y` to `big_c`, and no consistency check against the participant's public key share. The coordinator simply sums whatever bytes arrive over the channel.

**Attacker-controlled entry path:**

A malicious participant calls `ckd(...)` with a valid key pair but, instead of executing `compute_signature_share` honestly, sends an arbitrary pair `(big_y', big_c')` to the coordinator via `chan.send_private`. The coordinator's `recv_from_others` loop at line 50 accepts this message without any validation and folds it into `norm_big_y` and `norm_big_c`. [3](#0-2) 

### Impact Explanation

The final `CKDOutput` is `(Y, C)` where the app is expected to recover the confidential key as `C − app_sk · Y = x · H(pk, app_id)`. If any participant injects a wrong `(big_y', big_c')`, the sum is corrupted:

```
Y_corrupt  = Y_honest + (big_y' − lambda_i * y_i * G)
C_corrupt  = C_honest + (big_c' − lambda_i * (x_i * H + y_i * app_pk))
```

The app's decryption then yields a random, wrong group element instead of the intended confidential key. This is a **corruption of CKD output** matching the allowed High impact: *"Corruption of DKG, reshare, refresh, presign, sign, or CKD outputs so honest parties accept … unusable cryptographic outputs."*

### Likelihood Explanation

The CKD protocol requires **all** `n` participants to contribute; there is no threshold that tolerates even one malicious contributor. A single malicious participant — reachable without any privileged access, simply by participating in the protocol — can deterministically corrupt every CKD invocation they are part of. No leaked keys or cryptographic breaks are required.

### Recommendation

Add a zero-knowledge proof of correct formation to each participant's contribution before the coordinator accumulates it. Concretely, each participant should prove in zero knowledge that:

1. `big_y = lambda_i * y_i * G` for some scalar `y_i` they know (a Schnorr PoK on `big_y`).
2. `big_c` is a valid ElGamal ciphertext under `app_pk` with randomness `lambda_i * y_i` and plaintext `lambda_i * x_i * H(pk, app_id)` (a sigma protocol tying `big_c`, `big_y`, and the participant's public key share together).

The coordinator must verify these proofs before adding any contribution to the running sum, following the check-then-effect ordering.

### Proof of Concept

1. Malicious participant `P_m` calls `ckd(participants, coordinator, me, key_pair, app_id, app_pk, rng)`.
2. Instead of calling `compute_signature_share` honestly, `P_m` sends `(ElementG1::identity(), arbitrary_point)` to the coordinator.
3. The coordinator's loop at line 50–55 adds `ElementG1::identity()` to `norm_big_y` and `arbitrary_point` to `norm_big_c`.
4. The returned `CKDOutput` is `(Y_honest + 0, C_honest + arbitrary_point − lambda_m * (x_m * H + y_m * app_pk))`.
5. The app calls `ckd_output.unmask(app_sk)` and obtains a wrong group element, permanently failing to derive the intended confidential key for this `app_id`. [4](#0-3)

### Citations

**File:** src/confidential_key_derivation/protocol.rs (L26-33)
```rust
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
