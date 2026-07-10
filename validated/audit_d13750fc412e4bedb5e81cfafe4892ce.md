### Title
Malicious Participant Can Corrupt CKD Output by Injecting Arbitrary Shares Without Verification — (File: `src/confidential_key_derivation/protocol.rs`)

---

### Summary

The CKD coordinator aggregates per-participant contributions (`big_y`, `big_c`) by simple addition with no cryptographic verification that each contribution was honestly computed. Any single malicious participant can inject arbitrary group elements, causing the coordinator to output a structurally valid but cryptographically incorrect `CKDOutput`. Honest parties accept this corrupted output and derive a wrong confidential key, permanently breaking the CKD invariant for that session.

---

### Finding Description

The CKD protocol is a one-round additive aggregation. Each participant computes a normalized share `(λ_i · Y_i, λ_i · C_i)` and sends it privately to the coordinator. The coordinator sums all received values and returns the result.

In `do_ckd_coordinator` the aggregation loop is:

```rust
for (_, participant_output) in
    recv_from_others::<CKDOutput>(&chan, waitpoint, &participants, me).await?
{
    norm_big_y += participant_output.big_y();
    norm_big_c += participant_output.big_c();
}
``` [1](#0-0) 

There is no check that `participant_output.big_y()` equals `λ_i · y_i · G` for any honest `y_i`, and no check that `participant_output.big_c()` equals `λ_i · (x_i · H(pk, app_id) + y_i · A)`. The coordinator blindly adds whatever bytes arrive over the channel.

The honest computation each participant is supposed to perform is:

```rust
let big_y = ElementG1::generator() * y.0;
let big_s = hash_point * private_share.to_scalar();
let big_c = big_s + app_pk * y.0;
let norm_big_y = big_y * lambda_i;
let norm_big_c = big_c * lambda_i;
``` [2](#0-1) 

A malicious participant replaces this with any two arbitrary `G1` points and sends them. Because the channel delivers raw deserialized bytes and the coordinator performs no algebraic consistency check, the injected values are accepted and folded into the aggregate.

The final output `CKDOutput { big_y, big_c }` is then returned to the caller:

```rust
let ckd_output = CKDOutput::new(norm_big_y, norm_big_c);
Ok(Some(ckd_output))
``` [3](#0-2) 

The caller uses `unmask` to recover the confidential key as `C − a · Y`. With a corrupted `(Y, C)` the result is an arbitrary group element unrelated to `msk · H(pk, app_id)`.

---

### Impact Explanation

**High — Corruption of CKD outputs so honest parties accept unusable or inconsistent cryptographic outputs.**

The CKD protocol's security guarantee is that the coordinator outputs exactly `msk · H(pk, app_id)` (masked by the app's ephemeral key). A single malicious participant destroys this guarantee for the entire session. The coordinator and all downstream consumers of `CKDOutput::unmask` silently receive a wrong key with no error signal. There is no retry or detection mechanism; the session is permanently corrupted.

---

### Likelihood Explanation

Any participant in the protocol — not just the coordinator — can trigger this. The attacker-controlled entry path is:

1. Attacker is admitted as a legitimate participant (threshold assumption allows up to `t-1` malicious parties).
2. Attacker's instance of `do_ckd_participant` sends hand-crafted `(big_y, big_c)` bytes instead of the honest computation.
3. The coordinator's `recv_from_others` loop deserializes and accumulates the values without any check.

No special privilege is required beyond being a listed participant. The attack is single-round and requires no interaction beyond the normal protocol flow.

---

### Recommendation

Add a zero-knowledge proof of correct share computation alongside each `(big_y, big_c)` contribution. Concretely, each participant should prove in zero knowledge that:

- `big_y = y · G` for some `y` they know, and
- `big_c = x_i · H(pk, app_id) + y · A` using the same `y` and their committed signing share `x_i`.

A standard Sigma protocol (Chaum–Pedersen or a two-statement Schnorr proof) suffices. The coordinator must verify all proofs before aggregating. This mirrors how the DKG already requires a Proof of Knowledge for each polynomial commitment before accepting it:

```rust
verify_proof_of_knowledge(
    &session_id,
    &mut proof_domain_separator.clone(),
    threshold,
    p,
    old_participants.clone(),
    commitment_i,
    proof_i.as_ref(),
)?;
``` [4](#0-3) 

The CKD aggregation loop should adopt the same pattern.

---

### Proof of Concept

```
Honest protocol:
  norm_big_y = λ_i · y_i · G
  norm_big_c = λ_i · (x_i · H(pk, app_id) + y_i · A)

Malicious participant sends instead:
  norm_big_y = G          (identity or any arbitrary point)
  norm_big_c = G

Coordinator computes:
  total_Y = Σ_{honest j} λ_j · y_j · G  +  G          (poisoned)
  total_C = Σ_{honest j} λ_j · C_j      +  G          (poisoned)

unmask(app_sk) = total_C − app_sk · total_Y
               ≠ msk · H(pk, app_id)

The derived confidential key is wrong. No error is raised.
```

### Citations

**File:** src/confidential_key_derivation/protocol.rs (L50-55)
```rust
    for (_, participant_output) in
        recv_from_others::<CKDOutput>(&chan, waitpoint, &participants, me).await?
    {
        norm_big_y += participant_output.big_y();
        norm_big_c += participant_output.big_c();
    }
```

**File:** src/confidential_key_derivation/protocol.rs (L56-57)
```rust
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
