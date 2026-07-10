### Title
Unverified Participant Contributions in CKD Protocol Allow Malicious Participant to Corrupt Derived Key Output - (File: src/confidential_key_derivation/protocol.rs)

### Summary
The CKD protocol's coordinator unconditionally aggregates cryptographic contributions from all participants without any proof of correctness. A single malicious participant can send an arbitrary `(norm_big_y, norm_big_c)` pair, causing every honest party to accept a corrupted CKD output and derive an incorrect confidential key.

### Finding Description
In `do_ckd_participant`, each participant computes a share contribution and sends it privately to the coordinator:

```rust
fn do_ckd_participant(...) -> Result<CKDOutputOption, ProtocolError> {
    let (norm_big_y, norm_big_c) =
        compute_signature_share(participants, me, key_pair, app_id, app_pk, rng)?;
    let waitpoint = chan.next_waitpoint();
    chan.send_private(waitpoint, coordinator, &(norm_big_y, norm_big_c))?;
    Ok(None)
}
``` [1](#0-0) 

No zero-knowledge proof or commitment is attached to the message. The coordinator in `do_ckd_coordinator` then blindly aggregates every received pair:

```rust
for (_, participant_output) in
    recv_from_others::<CKDOutput>(&chan, waitpoint, &participants, me).await?
{
    norm_big_y += participant_output.big_y();
    norm_big_c += participant_output.big_c();
}
``` [2](#0-1) 

There is no check that:
1. `norm_big_c` was computed as `(hash_point * private_share + app_pk * y) * lambda_i` using the participant's actual registered private share.
2. `norm_big_y` and `norm_big_c` are consistent — i.e., that the same ephemeral scalar `y` was used for both.

The correct computation inside `compute_signature_share` is:

```
big_s  = hash_point * private_share
big_c  = big_s + app_pk * y
norm_big_y = big_y * lambda_i
norm_big_c = big_c * lambda_i
``` [3](#0-2) 

Because the coordinator performs no verification before aggregating, a malicious participant is free to substitute any group elements it chooses.

This is the direct analog of the `PolicyBook` giving `MAX_INT` DAI allowance to `bmiDaiStaking` and `claimVoting`: just as those contracts could drain the balance at will without the `PolicyBook`'s involvement, a malicious CKD participant can inject arbitrary additive offsets into the aggregated output at will, without any involvement or detection by the coordinator or other honest participants.

### Impact Explanation
The final `CKDOutput` is `(Σ norm_big_y_i, Σ norm_big_c_i)`. The app unmasks it as:

```
Σ norm_big_c_i − app_sk · Σ norm_big_y_i  =  msk · H(pk ∥ app_id)
``` [4](#0-3) 

If a malicious participant substitutes `norm_big_c' = norm_big_c + Δ` for an arbitrary group element `Δ`, the unmasked result becomes `msk · H(pk ∥ app_id) + Δ` — a completely wrong confidential key. The honest coordinator and all honest participants accept this corrupted output with no error. This maps directly to **High: Corruption of CKD outputs so honest parties accept unusable or inconsistent cryptographic outputs**.

### Likelihood Explanation
Any single participant in the CKD protocol can trigger this. No special privilege, leaked key, or cryptographic break is required — the attacker simply sends a malformed `(norm_big_y, norm_big_c)` message. The protocol has no round that would expose or penalise the deviation.

### Recommendation
Require each participant to attach a non-interactive zero-knowledge proof of well-formedness alongside their contribution. Specifically, each participant should prove in zero-knowledge that:
- `norm_big_y = y · G · lambda_i` for some scalar `y`, and
- `norm_big_c = (hash_point · private_share + app_pk · y) · lambda_i` using the same `y` and the private share committed to during DKG.

A standard Sigma protocol (e.g., a Chaum–Pedersen proof of discrete-log equality) over the BLS12-381 G1 group is sufficient. The coordinator must verify all proofs before aggregating, analogous to how the DKG protocol verifies proofs of knowledge before accepting polynomial commitments. [5](#0-4) 

### Proof of Concept
1. Run the CKD protocol with 3 participants, one of which is malicious.
2. The malicious participant, instead of calling `compute_signature_share`, sends `(G, G)` (the generator point for both components) to the coordinator.
3. The coordinator aggregates: `norm_big_y_total = honest_sum_y + G`, `norm_big_c_total = honest_sum_c + G`.
4. The app calls `unmask(app_sk)`: result is `honest_sum_c + G − app_sk · (honest_sum_y + G) = msk·H(pk∥app_id) + G − app_sk·G`, which is not equal to `msk·H(pk∥app_id)`.
5. The protocol returns `Ok(Some(ckd_output))` with no error — the corruption is silent and undetectable. [6](#0-5)

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

**File:** src/confidential_key_derivation/mod.rs (L54-56)
```rust
    pub fn unmask(&self, secret_scalar: Scalar) -> Signature {
        self.big_c - self.big_y * secret_scalar
    }
```

**File:** src/dkg.rs (L452-460)
```rust
        verify_proof_of_knowledge(
            &session_id,
            &mut proof_domain_separator.clone(), // you want to have the same state
            threshold,
            p,
            old_participants.clone(),
            commitment_i,
            proof_i.as_ref(),
        )?;
```
