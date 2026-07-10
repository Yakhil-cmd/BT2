### Title
Malicious CKD Participant Can Corrupt CKD Output by Sending Arbitrary Group Elements - (File: src/confidential_key_derivation/protocol.rs)

### Summary
The CKD coordinator blindly accumulates `(norm_big_y, norm_big_c)` contributions from participants with no cryptographic verification of their correctness. A single malicious participant can send arbitrary group elements — including the identity element — to corrupt the final `CKDOutput`, causing honest parties to derive an incorrect confidential key. This is the direct analog of the external report: just as `SwellLib.BOT` could pass `_processedRate = 0` to corrupt a withdrawal, a malicious CKD participant can pass `(G1::identity(), G1::identity())` to corrupt the CKD output.

### Finding Description

In `do_ckd_coordinator`, the coordinator receives each participant's `(norm_big_y, norm_big_c)` pair and sums them unconditionally:

```rust
for (_, participant_output) in
    recv_from_others::<CKDOutput>(&chan, waitpoint, &participants, me).await?
{
    norm_big_y += participant_output.big_y();
    norm_big_c += participant_output.big_c();
}
let ckd_output = CKDOutput::new(norm_big_y, norm_big_c);
``` [1](#0-0) 

An honest participant computes these values in `compute_signature_share` as:
- `norm_big_y = lambda_i * y_i * G` (a random blinding term)
- `norm_big_c = lambda_i * (x_i * H(pk, app_id) + y_i * app_pk)` (the masked key share) [2](#0-1) 

However, the coordinator performs **no verification** that the received values satisfy this relationship. A malicious participant can substitute any arbitrary `ElementG1` values — including `G1::identity()` (the additive zero) — and the coordinator will silently incorporate them into the final output.

This is structurally identical to the external report's root cause: in `swEXIT::processWithdrawals`, the BOT passed an arbitrary `_processedRate` that was used without fetching the canonical value from `swETH::swETHToETHRate`. Here, a participant passes arbitrary `(big_y, big_c)` that are used without verifying they were derived from the participant's actual key share.

Critically, unlike the OT-based and robust ECDSA signing protocols — which both verify the final signature against the public key and thus catch incorrect contributions at the end — the CKD protocol has **no analogous final correctness check**. The `CKDOutput` is returned directly to the caller: [3](#0-2) 

Compare with the OT-based ECDSA coordinator, which rejects a corrupted result: [4](#0-3) 

No equivalent guard exists in the CKD coordinator path.

### Impact Explanation

The coordinator produces a `CKDOutput` that is the sum of all contributions. A malicious participant sending `(G1::identity(), G1::identity())` causes their share of `msk * H(pk, app_id)` to be silently dropped. When the application calls `CKDOutput::unmask(app_sk)`:

```rust
pub fn unmask(&self, secret_scalar: Scalar) -> Signature {
    self.big_c - self.big_y * secret_scalar
}
``` [5](#0-4) 

it derives an incorrect confidential key instead of the expected `msk * H(pk, app_id)`. The honest coordinator and application have no way to detect this corruption. This matches the allowed impact: **High — Corruption of CKD outputs so honest parties accept unusable cryptographic outputs**.

### Likelihood Explanation

Any single participant in the CKD protocol can trigger this with zero cryptographic effort — they simply send a malformed message. No special knowledge, key material, or computational capability is required. The protocol imposes no minimum honesty assumption and provides no mechanism to identify or exclude the malicious contributor.

### Recommendation

Add a zero-knowledge proof of correct formation alongside each participant's `(norm_big_y, norm_big_c)` contribution, proving knowledge of `(y_i, x_i)` such that the Diffie-Hellman relationship holds between `norm_big_y`, `norm_big_c`, and the participant's public key share. The coordinator must verify all proofs before summing. Alternatively, add a final output consistency check analogous to the signature verification used in the ECDSA signing protocols.

### Proof of Concept

1. Instantiate a CKD protocol with 3 participants: coordinator `C`, honest participant `H`, malicious participant `M`.
2. `M` overrides `do_ckd_participant` to send `(G1::identity(), G1::identity())` to `C` instead of the correctly computed share.
3. `C` accumulates: `norm_big_y = C_big_y + H_big_y + 0`, `norm_big_c = C_big_c + H_big_c + 0`.
4. `C` returns `CKDOutput::new(norm_big_y, norm_big_c)` — missing `M`'s contribution to `msk`.
5. The application calls `ckd_output.unmask(app_sk)` and receives a value that differs from `msk * H(pk, app_id)`.
6. No error is raised; the corruption is silent and undetectable by honest parties.

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

**File:** src/ecdsa/ot_based_ecdsa/sign.rs (L128-134)
```rust
    // Spec 1.8
    if !sig.verify(&public_key, &msg_hash) {
        return Err(ProtocolError::AssertionFailed(
            "signature failed to verify".to_string(),
        ));
    }

```

**File:** src/confidential_key_derivation/mod.rs (L54-56)
```rust
    pub fn unmask(&self, secret_scalar: Scalar) -> Signature {
        self.big_c - self.big_y * secret_scalar
    }
```
