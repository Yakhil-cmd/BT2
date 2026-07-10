### Title
Missing Proof-of-Correctness Validation for Participant Contributions in CKD Protocol Allows Malicious Participant to Corrupt CKD Output - (File: src/confidential_key_derivation/protocol.rs)

### Summary
The Confidential Key Derivation (CKD) coordinator unconditionally accumulates ElGamal ciphertext components `(norm_big_y, norm_big_c)` received from each participant without any zero-knowledge proof or algebraic consistency check. A single malicious participant can send arbitrary group elements, silently corrupting the final CKD output that the coordinator returns to the application. Honest parties have no mechanism to detect or reject the manipulation.

### Finding Description

**Root cause — unvalidated participant-supplied cryptographic material**

Each participant computes and sends two group elements to the coordinator: [1](#0-0) 

```
norm_big_y = λ_i · y_i · G
norm_big_c = λ_i · (x_i · H(pk ‖ app_id) + y_i · app_pk)
```

The coordinator collects these values and sums them with no validation: [2](#0-1) 

```rust
for (_, participant_output) in
    recv_from_others::<CKDOutput>(&chan, waitpoint, &participants, me).await?
{
    norm_big_y += participant_output.big_y();
    norm_big_c += participant_output.big_c();
}
let ckd_output = CKDOutput::new(norm_big_y, norm_big_c);
```

There is no zero-knowledge proof that `norm_big_c` was formed using the participant's actual key share `x_i` and the agreed `app_pk`, and no proof that `norm_big_y` corresponds to the same randomness `y_i` used in `norm_big_c`. The participant-side function simply computes and sends the values with no accompanying proof: [3](#0-2) 

**Exploit path**

A malicious participant `P_m` replaces its honest contribution with arbitrary group elements, e.g. `(α·G, β·G)` for attacker-chosen scalars `α, β`. The coordinator sums these into the final output:

```
big_y_final  = Σ_{i≠m} λ_i·y_i·G  +  α·G
big_c_final  = Σ_{i≠m} λ_i·(x_i·H + y_i·app_pk)  +  β·G
```

The resulting `CKDOutput` is accepted by the coordinator and returned to the application. When the application calls `unmask(app_sk)`:

```
confidential_key = big_c_final − app_sk · big_y_final
                 = msk·H(pk,app_id) + (β − app_sk·α)·G   ← wrong
```

The derived confidential key is permanently wrong. No error is raised anywhere in the protocol.

### Impact Explanation

A single malicious participant causes the coordinator to accept and return a corrupted CKD output. The application (e.g., a TEE) derives an incorrect deterministic secret and uses it for encryption, authentication, or key derivation. The honest coordinator and all honest participants have no way to detect the manipulation. This matches the allowed High impact: **Corruption of CKD outputs so honest parties accept unusable or inconsistent cryptographic outputs**.

### Likelihood Explanation

Any participant in the CKD session is a reachable, unprivileged attacker. No special privilege is required beyond being a member of the participant set. The attack requires only sending two arbitrary group elements instead of the correct ones — a trivial modification to the protocol message. There is no retry, fallback, or output-verification step in the protocol that would surface the error.

### Recommendation

Add a Chaum-Pedersen (or equivalent) zero-knowledge proof of discrete-log equality alongside each participant's contribution, proving that `norm_big_y` and `norm_big_c` were formed with the same scalar `y_i` and that `norm_big_c` encodes the participant's actual key share `x_i`. The coordinator must verify all proofs before accumulating the values. Alternatively, adopt a verifiable secret-sharing approach where the coordinator can check each contribution against the participant's public verification share derived from the DKG output.

### Proof of Concept

1. Run a 3-participant CKD session with participants `P_1, P_2, P_3` and coordinator `P_1`.
2. `P_2` (malicious) intercepts its own outgoing message and replaces `(norm_big_y, norm_big_c)` with `(G, G)` (the generator point for both).
3. `P_1` (coordinator) receives the tampered message at: [4](#0-3) 
   and accumulates it without error.
4. The coordinator returns `CKDOutput::new(norm_big_y, norm_big_c)` where both components are shifted by `G`.
5. The application calls `unmask(app_sk)` and obtains `msk·H(pk,app_id) + (1 − app_sk)·G` — a value that differs from the correct confidential key by a known but attacker-controlled offset, permanently corrupting the derived secret.

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

**File:** src/confidential_key_derivation/protocol.rs (L47-57)
```rust
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

**File:** src/confidential_key_derivation/protocol.rs (L148-181)
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
```
