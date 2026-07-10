### Title
Malicious Participant Can Corrupt CKD Output by Sending Unchecked Arbitrary Group Elements - (File: src/confidential_key_derivation/protocol.rs)

### Summary
The CKD coordinator in `do_ckd_coordinator` accepts and accumulates `(big_y, big_c)` shares from all participants without any cryptographic validation. A single malicious participant can send arbitrary group elements, causing the coordinator to produce a CKD output that does not correspond to the actual master secret key, silently delivering a wrong confidential derived key to all honest parties.

### Finding Description
In `do_ckd_coordinator` (lines 44–57), the coordinator computes its own share via `compute_signature_share`, then receives shares from every other participant and blindly accumulates them:

```rust
for (_, participant_output) in
    recv_from_others::<CKDOutput>(&chan, waitpoint, &participants, me).await?
{
    norm_big_y += participant_output.big_y();
    norm_big_c += participant_output.big_c();
}
let ckd_output = CKDOutput::new(norm_big_y, norm_big_c);
``` [1](#0-0) 

There is no proof-of-correctness, commitment check, or any other validation that the received `(big_y_i, big_c_i)` values are honestly computed from the participant's key share `x_i` and a fresh random `y_i`. The correct relationship that should hold for each participant's contribution is:

- `big_y_i = lambda_i * y_i * G`
- `big_c_i = lambda_i * (x_i * H(pk, app_id) + y_i * app_pk)`

Neither of these is verified before accumulation.

Compare this to the OT-based ECDSA presign, which validates the summed `alpha` and `beta` values against public commitments before proceeding:

```rust
if (ProjectivePoint::GENERATOR * alpha != big_k + big_a)
    || (ProjectivePoint::GENERATOR * beta != big_x + big_b)
{
    return Err(ProtocolError::AssertionFailed(...));
}
``` [2](#0-1) 

The robust ECDSA presign similarly performs exponent interpolation checks on every received share before accepting it. [3](#0-2) 

The CKD protocol has no equivalent guard. A malicious participant can send `(identity, identity)` or any arbitrary pair of group elements; the coordinator will accept them and produce a `CKDOutput` whose `big_c` does not equal `msk * H(pk, app_id) + y * app_pk`. When the application calls `unmask(app_sk)`, it derives a wrong confidential key with no error or warning. [4](#0-3) 

### Impact Explanation
**High** — Corruption of CKD outputs so honest parties accept unusable cryptographic outputs. The derived confidential key will be incorrect, silently breaking any downstream use of the CKD output (key agreement, encryption, etc.). Honest parties have no way to detect the corruption because the coordinator does not broadcast individual contributions for cross-checking, and `CKDOutput::new` performs no internal consistency check. [5](#0-4) 

### Likelihood Explanation
Any single participant in the CKD protocol can trigger this. The CKD protocol has no threshold parameter — all listed participants must contribute, and any one of them can corrupt the result. The attack requires no special knowledge: sending the identity element for both `big_y` and `big_c` is sufficient and trivially constructable by any library caller who controls one participant's execution. [6](#0-5) 

### Recommendation
Add a zero-knowledge proof of correct share computation to each participant's message (e.g., a Schnorr-style proof that `big_c_i` is consistent with the participant's public key share and the published `app_pk`), or adopt a commitment-then-reveal scheme analogous to the DKG's commitment hash round so the coordinator can verify each `(big_y_i, big_c_i)` before accumulating it. [7](#0-6) 

### Proof of Concept
1. Honest participants P1, P2 and malicious participant P3 invoke `ckd(participants, coordinator, ...)`.
2. P3, instead of calling `compute_signature_share`, sends `chan.send_private(waitpoint, coordinator, &(identity, identity))`.
3. The coordinator executes the accumulation loop at lines 50–55 and adds `(identity, identity)` to the running sum — no error is raised.
4. The final `CKDOutput` equals `(big_y_P1 + big_y_P2, big_c_P1 + big_c_P2)`, missing P3's legitimate contribution, so `unmask(app_sk)` returns `(big_c_P1 + big_c_P2) - app_sk * (big_y_P1 + big_y_P2) ≠ msk * H(pk, app_id)`.
5. All honest parties accept this corrupted output with no error, and any system relying on the derived confidential key silently operates on a wrong value. [8](#0-7)

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

**File:** src/ecdsa/ot_based_ecdsa/presign.rs (L160-168)
```rust
    // beta*G =?= X + B
    // Spec 2.5
    if (ProjectivePoint::GENERATOR * alpha != big_k + big_a)
        || (ProjectivePoint::GENERATOR * beta != big_x + big_b)
    {
        return Err(ProtocolError::AssertionFailed(
            "received incorrect shares of additive triple phase.".to_string(),
        ));
    }
```

**File:** src/ecdsa/robust_ecdsa/presign.rs (L193-213)
```rust
    // check that the exponent interpolations match what has been received
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

**File:** src/dkg.rs (L407-415)
```rust
    // hash commitment and send it
    // Step 2.8
    let commit_domain_separator = domain_separator.clone();
    let commitment_hash =
        domain_separate_hash(&mut domain_separator, &(&me, &commitment, &session_id))?;

    // Step 2.9
    let wait_round_1 = chan.next_waitpoint();
    chan.send_many(wait_round_1, &commitment_hash)?;
```
