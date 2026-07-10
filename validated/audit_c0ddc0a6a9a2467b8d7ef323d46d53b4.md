### Title
Malicious CKD Participant Can Send Unverified Shares to Silently Corrupt the Coordinator's Derived Key Output - (File: src/confidential_key_derivation/protocol.rs)

### Summary
In the CKD protocol, each participant sends `(norm_big_y, norm_big_c)` to the coordinator with no zero-knowledge proof or commitment binding those values to the participant's private share or the agreed-upon `app_pk`. A single malicious participant can send arbitrary group elements, silently corrupting the coordinator's `CKDOutput` and making the derived confidential key irrecoverable.

### Finding Description
In `do_ckd_coordinator()`, the coordinator receives `CKDOutput` values from every other participant via `recv_from_others` and unconditionally accumulates them: [1](#0-0) 

The values `norm_big_y = λ_i · y_i · G` and `norm_big_c = λ_i · (S_i + y_i · app_pk)` are supposed to be computed in `compute_signature_share()` using the participant's private share and the agreed-upon `app_pk`: [2](#0-1) 

However, no proof of correct computation is attached to these values. No ZKP, no Pedersen commitment, and no cross-participant hash of `app_pk` is ever verified. The `app_pk` parameter flows into `compute_signature_share()` as a plain function argument with zero binding to any transcript: [3](#0-2) 

A malicious participant can:
1. Substitute a different `app_pk'` in their local `compute_signature_share()` call, producing a `big_c` that encodes a different masking key.
2. Or simply send arbitrary group elements `(G, G)` as their share.

In either case, the coordinator sums the tampered values with the honest participants' shares and returns a `CKDOutput` that does not correspond to `msk · H(pk, app_id)`. When the application calls `unmask(app_sk)`, it recovers a wrong value: [4](#0-3) 

The root cause is structurally identical to the Hinkal analog: a protocol input (`app_pk` / the participant's share pair) is consumed by the computation but is never bound to any transcript hash or proof that other parties verify. Compare this to the DKG protocol, which uses `commitment_hash` and `proof_of_knowledge` to bind every participant's contribution: [5](#0-4) 

No equivalent binding exists in the CKD protocol.

### Impact Explanation
The coordinator's `CKDOutput` is silently corrupted. `unmask(app_sk)` returns a random group element instead of `msk · H(pk, app_id)`. Any TEE application relying on this derived secret receives a wrong key, making the CKD protocol's output permanently unusable for that invocation. This matches **High: Corruption of CKD outputs so honest parties accept unusable cryptographic outputs**.

### Likelihood Explanation
Any single malicious participant — the documented adversary model for threshold protocols — can trigger this with a trivial one-line protocol deviation: substitute `app_pk` with any other group element before calling `compute_signature_share()`. No cryptographic break is required. The attack is completely undetectable because the coordinator has no mechanism to verify the received shares against the agreed-upon `app_pk`.

### Recommendation
Attach a zero-knowledge proof of correct computation to each participant's `(norm_big_y, norm_big_c)` message, proving:
- `norm_big_y = λ_i · y_i · G` for some `y_i` (standard discrete-log proof)
- `norm_big_c = λ_i · (x_i · H(pk, app_id) + y_i · app_pk)` (proof of linear relation over the agreed `app_pk`)

Alternatively, include `app_pk` in a broadcast transcript hash (analogous to the DKG's `session_id` / `commitment_hash` mechanism at `src/dkg.rs` lines 408–415) so all participants commit to the same `app_pk` before sending their shares, and the coordinator can reject any participant whose share was computed under a different key.

### Proof of Concept
1. Run the CKD protocol with 3 participants (P1, P2, P3) where P3 is malicious.
2. P3 deviates in `compute_signature_share()` by substituting `app_pk' = ElementG1::generator()` (the group generator) instead of the real `app_pk`.
3. P3 sends `(norm_big_y', norm_big_c')` — computed with `app_pk'` — to the coordinator.
4. The coordinator at lines 50–55 sums all shares: `big_c = big_c_P1 + big_c_P2 + big_c_P3'`.
5. `unmask(app_sk)` returns `msk · H(pk, app_id) + λ_3 · y_3 · (app_pk' − app_pk)` — a corrupted, unpredictable value.
6. No error is raised; the coordinator accepts the output as valid and returns it to the caller.

### Citations

**File:** src/confidential_key_derivation/protocol.rs (L17-32)
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
```

**File:** src/confidential_key_derivation/protocol.rs (L50-55)
```rust
    for (_, participant_output) in
        recv_from_others::<CKDOutput>(&chan, waitpoint, &participants, me).await?
    {
        norm_big_y += participant_output.big_y();
        norm_big_c += participant_output.big_c();
    }
```

**File:** src/confidential_key_derivation/protocol.rs (L168-181)
```rust
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

**File:** src/dkg.rs (L408-415)
```rust
    // Step 2.8
    let commit_domain_separator = domain_separator.clone();
    let commitment_hash =
        domain_separate_hash(&mut domain_separator, &(&me, &commitment, &session_id))?;

    // Step 2.9
    let wait_round_1 = chan.next_waitpoint();
    chan.send_many(wait_round_1, &commitment_hash)?;
```
