### Title
Malicious Participant Can Corrupt CKD Output by Sending Arbitrary Contribution Values Without Proof of Correctness — (File: `src/confidential_key_derivation/protocol.rs`)

---

### Summary
The `do_ckd_coordinator` function in `src/confidential_key_derivation/protocol.rs` aggregates `(big_y, big_c)` contributions from all participants without any proof of correctness. Because no zero-knowledge proof or commitment binding is required, a single malicious participant can send arbitrary group elements, causing the coordinator to compute a structurally valid but cryptographically incorrect `CKDOutput`. The honest coordinator and all honest parties accept this corrupted output as final.

---

### Finding Description

In `do_ckd_coordinator`, the coordinator first computes its own correct share: [1](#0-0) 

It then collects one `CKDOutput` from every other participant via `recv_from_others` and unconditionally adds each received `(big_y, big_c)` pair into the running sum: [2](#0-1) 

The helper `recv_from_others` enforces only that each participant sends exactly one message (deduplication via `ParticipantCounter`); it performs no content validation whatsoever: [3](#0-2) 

The correct contribution from participant `i` is:

```
norm_big_y_i = λ_i · y_i · G
norm_big_c_i = λ_i · (x_i · H(pk ‖ app_id) + y_i · app_pk)
```

computed inside `compute_signature_share`: [4](#0-3) 

Nothing in the protocol binds the received `(big_y, big_c)` to the participant's actual private share `x_i` or to the random nonce `y_i`. A malicious participant may substitute any pair of group elements.

---

### Impact Explanation

The final `CKDOutput` is the sum of all contributions. When the coordinator calls `unmask(app_sk)` it computes:

```
confidential_key = big_c − app_sk · big_y
                 = msk · H(pk ‖ app_id)   (when all contributions are honest)
```

If one participant injects an arbitrary additive offset `(Δ_Y, Δ_C)`, the recovered key becomes:

```
(big_c + Δ_C) − app_sk · (big_y + Δ_Y)
= msk · H(pk ‖ app_id) + (Δ_C − app_sk · Δ_Y)
```

The coordinator and all downstream consumers accept this corrupted value as the legitimate confidential derived key. This maps directly to the allowed High impact: **Corruption of CKD outputs so honest parties accept incorrect cryptographic outputs**.

---

### Likelihood Explanation

Any single participant in the CKD protocol can trigger this. The attacker needs only to replace their honest `do_ckd_participant` call with one that sends a crafted `CKDOutput` to the coordinator. No special privilege, no key material from other parties, and no cryptographic break is required. The coordinator has no mechanism to detect the substitution. [5](#0-4) 

---

### Recommendation

Require each participant to accompany their `(big_y, big_c)` contribution with a Sigma-protocol (e.g., a Chaum-Pedersen proof) demonstrating that:

1. `big_y = λ_i · y_i · G` for some `y_i` they know, and
2. `big_c − big_y · (app_pk / G) = λ_i · x_i · H(pk ‖ app_id)` (i.e., the share component is consistent with the public commitment to `x_i` established during DKG).

The coordinator must verify all proofs before aggregating. This is the standard pattern used in the DKG module, where every participant's polynomial commitment is accompanied by a proof of knowledge verified before shares are accepted: [6](#0-5) 

---

### Proof of Concept

```
Setup: 3 participants P0 (coordinator), P1, P2; honest DKG completed.

Attack:
  P1 (malicious) overrides do_ckd_participant:
    Instead of computing correct (norm_big_y, norm_big_c),
    sends CKDOutput { big_y: G, big_c: G }   // arbitrary non-zero elements

Coordinator aggregation (do_ckd_coordinator, lines 50-55):
  norm_big_y = (λ0·y0·G) + G          + (λ2·y2·G)
  norm_big_c = (λ0·(x0·H+y0·A)) + G  + (λ2·(x2·H+y2·A))

unmask(app_sk):
  result = norm_big_c − app_sk·norm_big_y
         = msk·H(pk‖app_id) + G − app_sk·G
         ≠ msk·H(pk‖app_id)

The coordinator outputs and accepts a corrupted confidential key.
No error is raised; the protocol completes successfully.
```

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

**File:** src/confidential_key_derivation/protocol.rs (L44-45)
```rust
    let (mut norm_big_y, mut norm_big_c) =
        compute_signature_share(&participants, me, key_pair, app_id, app_pk, rng)?;
```

**File:** src/confidential_key_derivation/protocol.rs (L50-56)
```rust
    for (_, participant_output) in
        recv_from_others::<CKDOutput>(&chan, waitpoint, &participants, me).await?
    {
        norm_big_y += participant_output.big_y();
        norm_big_c += participant_output.big_c();
    }
    let ckd_output = CKDOutput::new(norm_big_y, norm_big_c);
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

**File:** src/protocol/helpers.rs (L15-26)
```rust
    let mut seen = ParticipantCounter::new(participants);
    seen.put(me);
    let mut messages = Vec::with_capacity(participants.others(me).count());

    while !seen.full() {
        let (from, msg) = chan.recv(waitpoint).await?;
        if seen.put(from) {
            messages.push((from, msg));
        }
    }

    Ok(messages)
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
