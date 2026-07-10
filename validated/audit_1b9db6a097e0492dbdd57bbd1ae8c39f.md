### Title
Unverified Participant Contributions in CKD Coordinator Allow Malicious Participant to Corrupt Derived Key Output - (File: src/confidential_key_derivation/protocol.rs)

### Summary
The CKD coordinator directly accumulates elliptic-curve group elements received from participants without any proof of correct computation. A malicious participant can send arbitrary `big_y` and `big_c` values, causing the coordinator to produce a `CKDOutput` that decrypts to a key other than `msk · H(pk, app_id)`.

### Finding Description

In `do_ckd_coordinator`, the coordinator receives each participant's `(norm_big_y, norm_big_c)` pair and unconditionally adds them into the running totals: [1](#0-0) 

```rust
for (_, participant_output) in
    recv_from_others::<CKDOutput>(&chan, waitpoint, &participants, me).await?
{
    norm_big_y += participant_output.big_y();
    norm_big_c += participant_output.big_c();
}
```

Each honest participant is supposed to compute:

- `big_y_i = y_i · G`
- `big_c_i = x_i · H(pk, app_id) + y_i · app_pk`

and then Lagrange-normalize both before sending. [2](#0-1) 

There is no zero-knowledge proof or consistency check that the received `big_c` was formed using the participant's actual signing share `x_i` and the same ephemeral scalar `y_i` used for `big_y`. The coordinator has no way to distinguish a correctly-formed contribution from an arbitrary group element.

The final `CKDOutput` is:

```
big_C = Σ λ_i · (x_i · H(pk, app_id) + y_i · app_pk)
      = msk · H(pk, app_id) + y · app_pk
```

If participant `j` replaces its honest `big_c_j` with `big_c_j + δ` for an arbitrary group element `δ`, the coordinator computes:

```
big_C' = msk · H(pk, app_id) + y · app_pk + δ
```

After the application decrypts with `app_sk`:

```
big_C' - app_sk · big_Y = msk · H(pk, app_id) + δ
```

The derived key is shifted by `δ`, which is fully attacker-controlled.

### Impact Explanation

**High — Corruption of CKD output.** A single malicious participant can cause every honest party (including the coordinator) to accept a `CKDOutput` whose decrypted value is not `msk · H(pk, app_id)`. The application will silently derive and use a wrong key. This matches the allowed impact: *"Corruption of … CKD outputs so honest parties accept … unusable cryptographic outputs."*

If the malicious participant also controls or learns `app_sk` (e.g., a compromised TEE application), they can choose `δ` to make the decrypted output equal any target point, constituting unauthorized creation of a derived key (Critical).

### Likelihood Explanation

Any single participant in the CKD protocol can trigger this. The entry path requires no special privilege: `ckd()` is a public API, and any participant that deviates from the protocol during the single communication round can corrupt the output. The coordinator performs no verification before assembling the final result. [3](#0-2) 

### Recommendation

Each participant must accompany its `(norm_big_y, norm_big_c)` with a non-interactive zero-knowledge proof of correct formation — specifically a proof that:

1. `big_y_i` is a scalar multiple of the generator (`big_y_i = y_i · G`), and
2. `big_c_i` was formed as `x_i · H(pk, app_id) + y_i · app_pk` using the same `y_i` and the participant's committed signing share `x_i`.

A standard Chaum–Pedersen proof (or a sigma protocol over the two-base relation) suffices. The coordinator must verify all proofs before accumulating contributions, analogous to how `validate_received_share` is used in DKG to verify each secret share against the public commitment before summing. [4](#0-3) 

### Proof of Concept

1. Honest participants `{P1, P2, P3}` run `ckd()` with coordinator `P1`.
2. `P2` is malicious. Instead of calling `compute_signature_share` honestly, it sends `(norm_big_y_2, norm_big_c_2 + δ)` where `δ` is an arbitrary non-zero group element.
3. The coordinator at line 53–54 adds the tampered values without any check.
4. The resulting `CKDOutput` satisfies `ckd_output.unmask(app_sk) = msk · H(pk, app_id) + δ ≠ msk · H(pk, app_id)`.
5. The application silently uses the wrong derived key; no error is raised anywhere in the protocol. [5](#0-4)

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

**File:** src/confidential_key_derivation/protocol.rs (L159-181)
```rust
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
