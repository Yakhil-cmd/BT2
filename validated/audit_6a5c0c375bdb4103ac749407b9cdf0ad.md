### Title
Malicious CKD Participant Can Corrupt Coordinator's Aggregated Output Without Detection — (`File: src/confidential_key_derivation/protocol.rs`)

---

### Summary

The CKD coordinator in `do_ckd_coordinator` blindly aggregates `(norm_big_y, norm_big_c)` shares received from every participant with no proof of correct formation. A single malicious participant can send arbitrary group elements, causing the coordinator to produce a permanently corrupted `CKDOutput` that decrypts to the wrong confidential key. Honest parties accept this output as valid because no post-aggregation or per-share verification exists.

---

### Finding Description

**Root cause — unverified share aggregation in `do_ckd_coordinator`**

`src/confidential_key_derivation/protocol.rs` lines 50–55:

```rust
for (_, participant_output) in
    recv_from_others::<CKDOutput>(&chan, waitpoint, &participants, me).await?
{
    norm_big_y += participant_output.big_y();
    norm_big_c += participant_output.big_c();
}
```

Each honest participant is supposed to compute and send:

```
big_y  = y_i · G
big_c  = x_i · H(pk ‖ app_id) + y_i · app_pk
norm_big_y = λ_i · big_y
norm_big_c = λ_i · big_c
```

The coordinator sums all `norm_big_y` and `norm_big_c` values and returns the result as the final `CKDOutput`. There is **no zero-knowledge proof, no consistency check, and no post-aggregation verification** that any participant's contribution is correctly formed.

**Contrast with DKG** — `src/dkg.rs` performs `verify_proof_of_knowledge`, `verify_commitment_hash`, and `validate_received_share` on every participant's contribution before accepting it. The CKD protocol has no equivalent step.

**Attack path**

1. A malicious participant is legitimately enrolled in the CKD participant list (no privilege required).
2. Instead of computing the correct `(norm_big_y, norm_big_c)`, it sends arbitrary group elements `(G_bad, G_bad)` to the coordinator.
3. The coordinator's loop at lines 50–55 adds these values into the running sums without any check.
4. The final `CKDOutput` returned at line 56 is `(Y_corrupted, C_corrupted)`.
5. When the application calls `ckd_output.unmask(app_sk)`, it computes `C_corrupted − app_sk · Y_corrupted`, which does **not** equal `msk · H(pk ‖ app_id)`.
6. The honest coordinator and all honest callers receive and accept this wrong output — there is no mechanism to detect the corruption.

The `do_ckd_participant` function (`src/confidential_key_derivation/protocol.rs` lines 17–33) is a non-async function that simply sends its share and returns `Ok(None)` — it never learns the final output and cannot raise an alarm.

---

### Impact Explanation

A single malicious participant causes the coordinator to output a permanently wrong confidential derived key. Every honest party that consumes this output (e.g., a TEE application decrypting a secret) receives an incorrect result. Because the protocol has no output-verification step, honest parties cannot distinguish a corrupted output from a correct one. This matches the allowed **High** impact: *"Corruption of CKD outputs so honest parties accept inconsistent or unusable cryptographic outputs."*

---

### Likelihood Explanation

Any participant enrolled in the CKD protocol can execute this attack with no privileged access. The attacker only needs to be a valid member of the `participants` list, which is the normal operating condition. The attack requires sending two arbitrary group elements — a trivial one-round action.

---

### Recommendation

Add a per-share proof of correct ElGamal encryption before the coordinator aggregates contributions. Concretely, each participant should accompany `(norm_big_y, norm_big_c)` with a Chaum–Pedersen NIZK proving that the discrete-log relationship between `big_y` and `big_c` is consistent with the participant's committed public key share. The coordinator must verify each proof before adding the share to the running sum, mirroring the `validate_received_share` pattern already used in `src/dkg.rs`.

---

### Proof of Concept

**Honest execution** (lines 148–181, `protocol.rs`):
```
norm_big_c = λ_i · (x_i · H(pk‖app_id) + y_i · app_pk)
```
Summing over all honest participants gives `msk · H(pk‖app_id) + Y_total · app_sk`, which unmasks correctly.

**Malicious participant** replaces its contribution with `(G, G)` (the generator point):
```rust
// malicious participant sends:
let norm_big_y = ElementG1::generator();   // arbitrary
let norm_big_c = ElementG1::generator();   // arbitrary
chan.send_private(waitpoint, coordinator, &(norm_big_y, norm_big_c))?;
```

The coordinator's loop at lines 50–55 adds these without complaint:
```
Y_corrupted = Σ honest norm_big_y + G
C_corrupted = Σ honest norm_big_c + G
```

Unmasking: `C_corrupted − app_sk · Y_corrupted = msk · H(pk‖app_id) + G − app_sk · G ≠ msk · H(pk‖app_id)`.

The output is silently wrong. No error is returned. [1](#0-0) [2](#0-1) [3](#0-2)

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

**File:** src/dkg.rs (L259-286)
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
}
```
