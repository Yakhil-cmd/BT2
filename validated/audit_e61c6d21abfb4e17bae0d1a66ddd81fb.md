### Title
Unverified CKD Share Injection by Malicious Participant Corrupts Coordinator's Derived Confidential Key — (File: `src/confidential_key_derivation/protocol.rs`)

---

### Summary

In the Confidential Key Derivation (CKD) protocol, the coordinator receives `CKDOutput` shares `(big_y, big_c)` from each participant and accumulates them without any cryptographic verification. A malicious participant can send arbitrary group elements in place of their honest share. Because no zero-knowledge proof or commitment binding is checked, the coordinator silently accepts the injected values and derives a corrupted confidential key.

---

### Finding Description

The coordinator path `do_ckd_coordinator` collects participant outputs and sums them directly: [1](#0-0) 

```rust
for (_, participant_output) in
    recv_from_others::<CKDOutput>(&chan, waitpoint, &participants, me).await?
{
    norm_big_y += participant_output.big_y();
    norm_big_c += participant_output.big_c();
}
let ckd_output = CKDOutput::new(norm_big_y, norm_big_c);
```

Each honest participant is supposed to compute and send: [2](#0-1) 

```
big_y  = y_i * G
big_c  = x_i * H(pk || app_id) + y_i * app_pk
norm_big_y = lambda_i * big_y
norm_big_c = lambda_i * big_c
```

The coordinator then unmasks the aggregate as `big_c_total - app_sk * big_y_total = msk * H(pk || app_id)`.

There is **no proof of correct formation** attached to the participant's message — no Schnorr proof, no Pedersen commitment, no consistency check against the participant's public key share. The coordinator has no way to distinguish a correctly-formed share from an arbitrary pair of group elements.

A malicious participant calls `do_ckd_participant`, which sends `(norm_big_y, norm_big_c)` privately to the coordinator: [3](#0-2) 

The malicious participant can replace these with any two elements of G1, injecting an additive offset `(delta_y, delta_c)` into the coordinator's accumulator. The final unmasked key becomes:

```
msk * H(pk || app_id) + (delta_c - app_sk * delta_y)
```

which is not the correct derived key.

**Contrast with other protocols in the same codebase:** The OT-based ECDSA presign verifies received shares against public commitments before using them: [4](#0-3) 

The robust ECDSA presign performs exponent-interpolation consistency checks on every received share: [5](#0-4) 

The CKD coordinator path has no equivalent check.

---

### Impact Explanation

The coordinator is the only party that receives `Some(ckd_output)`. A single malicious participant can make the coordinator derive a wrong confidential key — one that does not equal `msk * H(pk || app_id)`. The TEE application that subsequently uses this key will operate on incorrect secret material. This matches the allowed impact:

> **High: Corruption of DKG, reshare, refresh, presign, sign, or CKD outputs so honest parties accept inconsistent public keys, participant sets, transcripts, or unusable cryptographic outputs.**

---

### Likelihood Explanation

Any participant in the CKD protocol can trigger this. The attacker only needs to be a registered participant (the standard trust assumption for threshold protocols). No special privilege, leaked key, or external dependency is required. The attack is a single-message substitution with no observable side-effect before the coordinator uses the output.

---

### Recommendation

Require each participant to attach a zero-knowledge proof of correct share formation alongside `(norm_big_y, norm_big_c)`. Concretely, a participant should prove knowledge of `(y_i, x_i)` such that:

- `norm_big_y = lambda_i * y_i * G`
- `norm_big_c = lambda_i * (x_i * H(pk || app_id) + y_i * app_pk)`
- `x_i * G2 = participant's public key share` (binding to the DKG output)

The coordinator must verify this proof before accumulating each participant's contribution, analogous to how `validate_received_share` is used in `do_keyshare`: [6](#0-5) 

---

### Proof of Concept

1. Honest setup: run DKG for 3 participants with threshold 2; obtain `(private_share_i, public_key)` for each.
2. Designate participant `P_malicious` as the attacker.
3. `P_malicious` overrides `do_ckd_participant` to send `(delta_y, delta_c)` = `(G, G)` (generator points) instead of the correctly computed share.
4. The coordinator accumulates: `norm_big_y_total = honest_sum_y + G`, `norm_big_c_total = honest_sum_c + G`.
5. `ckd_output.unmask(app_sk)` returns `msk * H(pk||app_id) + G - app_sk * G`, which is not the correct derived key.
6. Any downstream TEE operation using this key produces incorrect results, and the coordinator has no way to detect the corruption.

### Citations

**File:** src/confidential_key_derivation/protocol.rs (L27-32)
```rust
    let (norm_big_y, norm_big_c) =
        compute_signature_share(participants, me, key_pair, app_id, app_pk, rng)?;
    let waitpoint = chan.next_waitpoint();
    chan.send_private(waitpoint, coordinator, &(norm_big_y, norm_big_c))?;

    Ok(None)
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

**File:** src/ecdsa/ot_based_ecdsa/presign.rs (L127-131)
```rust
    if big_e != (ProjectivePoint::GENERATOR * e).to_affine() {
        return Err(ProtocolError::AssertionFailed(
            "received incorrect shares of kd".to_string(),
        ));
    }
```

**File:** src/ecdsa/robust_ecdsa/presign.rs (L194-213)
```rust
    for (identifier, verifying_share) in identifiers
        .iter()
        .skip(threshold + 1)
        .zip(verifying_shares.iter().skip(threshold + 1))
    {
        // Step 3.2
        // exponent interpolation for (R0, .., Rt; i)
        let big_r_i = PolynomialCommitment::eval_exponent_interpolation(
            threshold_plus1_identifiers,
            threshold_plus1_verifying_shares,
            Some(identifier),
        )?;

        // check the interpolated R values match the received ones
        if big_r_i != *verifying_share {
            return Err(ProtocolError::AssertionFailed(
                "Exponent interpolation check failed.".to_string(),
            ));
        }
    }
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
