### Title
Missing Validation of Participant CKD Share Elements Allows Malicious Participant to Corrupt Confidential Key Derivation Output — (File: `src/confidential_key_derivation/protocol.rs`)

---

### Summary

The `do_ckd_coordinator` function accumulates `big_y` and `big_c` group elements received from each participant without validating that they are non-identity. A malicious participant can send identity (zero) elements or arbitrary crafted group elements, causing the coordinator to produce a corrupted `CKDOutput`. When the application unmasks the result, it obtains an incorrect confidential derived key, permanently breaking CKD for that invocation.

---

### Finding Description

In `do_ckd_coordinator` (`src/confidential_key_derivation/protocol.rs`, lines 50–57), the coordinator receives a `CKDOutput` from every other participant and blindly adds the two group elements into running accumulators:

```rust
for (_, participant_output) in
    recv_from_others::<CKDOutput>(&chan, waitpoint, &participants, me).await?
{
    norm_big_y += participant_output.big_y();   // no validation
    norm_big_c += participant_output.big_c();   // no validation
}
let ckd_output = CKDOutput::new(norm_big_y, norm_big_c);
Ok(Some(ckd_output))
``` [1](#0-0) 

Neither the per-participant values nor the final accumulated `norm_big_y` / `norm_big_c` are checked to be non-identity before the `CKDOutput` is returned.

The protocol is an ElGamal-style masking scheme. Each honest participant `i` computes and sends:

```
norm_big_y_i = λ_i · y_i · G
norm_big_c_i = λ_i · (x_i · H(pk ‖ app_id) + y_i · A)
``` [2](#0-1) 

The coordinator sums these to obtain `(Y·G, msk·H + Y·A)`, and the application decrypts with `unmask(app_sk) = big_c − app_sk · big_y = msk·H`. [3](#0-2) 

Because there is **no commitment scheme** binding each participant's `(big_y, big_c)` pair to their private share (unlike the DKG, which uses `validate_received_share` against a polynomial commitment), a malicious participant is free to send any `CKDOutput` — including the identity element — and the coordinator will incorporate it without complaint. [4](#0-3) 

---

### Impact Explanation

**High — Corruption of CKD outputs so honest parties accept unusable cryptographic outputs.**

A malicious participant sends `CKDOutput::new(G1::identity(), G1::identity())`. The coordinator's accumulators are shifted by the identity, so the final `norm_big_y` and `norm_big_c` no longer satisfy the invariant `norm_big_c = msk·H + norm_big_y·app_sk`. When the application calls `unmask(app_sk)`, it obtains a value that is not `msk·H(pk ‖ app_id)`. The derived confidential key is silently wrong — the application has no way to detect this without an independent oracle for the correct key.

Because the CKD protocol is single-round (no broadcast-success vote analogous to DKG's `broadcast_success`), there is no mechanism for honest parties to detect or attribute the corruption. [5](#0-4) 

---

### Likelihood Explanation

**High.** Any participant in the CKD protocol — a role that requires no special privilege beyond being in the participant list — can trivially send identity elements. The attack requires no cryptographic knowledge, no key material, and no coordination. It succeeds deterministically on every invocation where the malicious participant is included.

---

### Recommendation

1. **Per-element validation**: After deserializing each participant's `CKDOutput`, reject identity elements immediately:

```rust
if participant_output.big_y().is_identity().into()
    || participant_output.big_c().is_identity().into()
{
    return Err(ProtocolError::AssertionFailed(
        "Participant sent identity element in CKD share".to_string(),
    ));
}
```

2. **Final accumulator validation**: After the loop, validate that `norm_big_y` and `norm_big_c` are non-identity before constructing `CKDOutput`.

3. **Consistency proof**: Consider requiring each participant to provide a zero-knowledge proof of consistency between `big_y` and `big_c` (i.e., that the same `y_i` was used in both), analogous to the proof-of-knowledge used in DKG.

---

### Proof of Concept

A malicious participant replaces its honest `compute_signature_share` output with:

```rust
// Malicious participant sends identity elements
chan.send_private(waitpoint, coordinator, &CKDOutput::new(
    ElementG1::identity(),
    ElementG1::identity(),
))?;
```

The coordinator at lines 50–57 adds these without any check. The resulting `norm_big_y` and `norm_big_c` are shifted away from their correct values. `unmask(app_sk)` returns an incorrect group element. The application silently uses a wrong confidential derived key. [6](#0-5)

### Citations

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

**File:** src/confidential_key_derivation/mod.rs (L54-56)
```rust
    pub fn unmask(&self, secret_scalar: Scalar) -> Signature {
        self.big_c - self.big_y * secret_scalar
    }
```

**File:** src/dkg.rs (L259-285)
```rust
fn validate_received_share<C: Ciphersuite>(
    me: Participant,
    from: Participant,
    signing_share_from: &SigningShare<C>,
    commitment: &VerifiableSecretSharingCommitment<C>,
) -> Result<(), ProtocolError> {
    let id = me.to_identifier::<C>()?;

    // The verification is exactly the same as the regular SecretShare verification;
    // however the required components are in different places.
    // Build a temporary SecretShare so what we can call verify().
    let secret_share = SecretShare::new(id, *signing_share_from, commitment.clone());

    // Verify the share. We don't need the result.
    // Identify the culprit if an InvalidSecretShare error is returned.
    secret_share.verify().map_err(|e| {
        if let Error::InvalidSecretShare { .. } = e {
            ProtocolError::InvalidSecretShare(from)
        } else {
            ProtocolError::AssertionFailed(format!(
                "could not
            extract the verification key matching the secret
            share sent by {from:?}"
            ))
        }
    })?;
    Ok(())
```
