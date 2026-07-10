### Title
Single Malicious CKD Participant Can Corrupt Aggregate Output Without Proof of Correctness — (`src/confidential_key_derivation/protocol.rs`)

---

### Summary

The Confidential Key Derivation (CKD) coordinator aggregates per-participant contributions `(big_y, big_c)` by simple addition, with no zero-knowledge proof or consistency check that each participant's `big_c` was honestly computed from their actual private share. A single malicious participant can send arbitrary group elements, silently corrupting the final CKD output accepted by the coordinator.

---

### Finding Description

In `do_ckd_coordinator`, the coordinator collects each participant's `(norm_big_y, norm_big_c)` and sums them unconditionally: [1](#0-0) 

```rust
for (_, participant_output) in
    recv_from_others::<CKDOutput>(&chan, waitpoint, &participants, me).await?
{
    norm_big_y += participant_output.big_y();
    norm_big_c += participant_output.big_c();
}
```

Each honest participant computes their share as: [2](#0-1) 

```
big_y  = y * G
big_c  = private_share * H(pk || app_id) + y * app_pk
norm_* = lambda_i * (big_y, big_c)
```

The correctness of `big_c` depends on the participant using their actual `private_share`. There is **no ZK proof** (e.g., a proof of discrete-log equality between `big_c - y * app_pk` and the participant's committed public key share) attached to the message sent to the coordinator. [3](#0-2) 

The participant simply sends the pair and returns `None` — no proof, no commitment binding, no verification step on the coordinator side.

The `unmask` operation recovers the confidential key as:

```
C_total - app_sk * Y_total  =  msk * H(pk || app_id)
```

If any single participant substitutes an arbitrary `(big_y_evil, big_c_evil)`, the aggregate becomes:

```
C_total = C_honest_rest + big_c_evil
Y_total = Y_honest_rest + big_y_evil
```

and `unmask` yields a value that is **not** `msk * H(pk || app_id)`, with no error or detection.

---

### Impact Explanation

The coordinator — and any downstream TEE consumer — silently accepts a corrupted CKD output. The derived confidential key is wrong and unusable. Because the protocol aggregates contributions from **all** participants (not a threshold subset), a single malicious participant is sufficient to corrupt every CKD invocation they participate in.

This falls squarely within the allowed High impact: **Corruption of CKD outputs so honest parties accept inconsistent or unusable cryptographic outputs.**

---

### Likelihood Explanation

Any participant enrolled in a CKD session is a reachable attacker. No special privilege, leaked key, or external assumption is required — the attacker only needs to deviate from the protocol by sending a malformed `CKDOutput`. The coordinator has no mechanism to detect or reject it.

---

### Recommendation

Require each participant to accompany their `(norm_big_y, norm_big_c)` with a zero-knowledge proof of correct formation — specifically, a proof of discrete-log equality demonstrating that `norm_big_c - norm_big_y * (app_pk / G)` lies on the same discrete-log relation as the participant's committed public key share. The coordinator must verify this proof before incorporating the contribution into the aggregate.

Alternatively, adopt a verifiable secret sharing approach where each participant's contribution can be checked against their public key share from the DKG output.

---

### Proof of Concept

1. Honest participants `P_1, …, P_{N-1}` run `compute_signature_share` correctly.
2. Malicious participant `P_N` sends `CKDOutput::new(ElementG1::identity(), ElementG1::identity())` (or any arbitrary pair) to the coordinator instead of their honest share.
3. The coordinator's loop at lines 50–55 adds these zero/arbitrary elements without complaint.
4. The final `CKDOutput` returned at line 56 is `(Y_honest + 0, C_honest + 0)` — missing `P_N`'s Lagrange-weighted secret contribution — so `unmask(app_sk)` returns a value different from `msk * H(pk || app_id)`.
5. The TEE application receives and uses a silently wrong confidential key with no indication of failure. [4](#0-3)

### Citations

**File:** src/confidential_key_derivation/protocol.rs (L27-32)
```rust
    let (norm_big_y, norm_big_c) =
        compute_signature_share(participants, me, key_pair, app_id, app_pk, rng)?;
    let waitpoint = chan.next_waitpoint();
    chan.send_private(waitpoint, coordinator, &(norm_big_y, norm_big_c))?;

    Ok(None)
```

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

**File:** src/confidential_key_derivation/protocol.rs (L165-180)
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
```
