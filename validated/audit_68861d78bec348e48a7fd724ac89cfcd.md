### Title
Malicious Participant Can Corrupt CKD Output by Sending Unverified Contributions Without Proof of Correct Key Usage - (File: src/confidential_key_derivation/protocol.rs)

### Summary
In `do_ckd_coordinator`, the coordinator accumulates each participant's `(norm_big_y, norm_big_c)` contribution directly into the final CKD output with no proof of correctness. Any malicious participant in the protocol can substitute an arbitrary scalar in place of their actual private share `x_i`, causing the coordinator and all honest parties to accept a corrupted confidential derived key.

### Finding Description
The CKD coordinator collects one `CKDOutput` from every other participant and sums them:

```rust
// src/confidential_key_derivation/protocol.rs, lines 50-56
for (_, participant_output) in
    recv_from_others::<CKDOutput>(&chan, waitpoint, &participants, me).await?
{
    norm_big_y += participant_output.big_y();
    norm_big_c += participant_output.big_c();
}
let ckd_output = CKDOutput::new(norm_big_y, norm_big_c);
```

Each honest participant `i` is supposed to compute:

```
norm_big_c_i = λ_i · (x_i · H(pk ‖ app_id) + y_i · app_pk)
```

where `x_i` is their actual private signing share. The coordinator then reconstructs the master secret contribution via Lagrange interpolation in the exponent. However, `do_ckd_participant` simply sends whatever it computes with no attached proof:

```rust
// src/confidential_key_derivation/protocol.rs, lines 29-31
let waitpoint = chan.next_waitpoint();
chan.send_private(waitpoint, coordinator, &(norm_big_y, norm_big_c))?;
```

There is no zero-knowledge proof, commitment binding, or any other mechanism that forces `norm_big_c_i` to embed the participant's actual `x_i`. A malicious participant can freely substitute `x_i' ≠ x_i` (including zero or any attacker-chosen scalar) and the coordinator has no way to detect this.

Contrast this with the DKG protocol in `src/dkg.rs`, which explicitly calls `verify_proof_of_knowledge` and `validate_received_share` before accepting any participant contribution:

```rust
// src/dkg.rs, lines 452-460
verify_proof_of_knowledge(
    &session_id,
    &mut proof_domain_separator.clone(),
    threshold,
    p,
    old_participants.clone(),
    commitment_i,
    proof_i.as_ref(),
)?;
```

No equivalent check exists in the CKD protocol.

### Impact Explanation
The final CKD output is:

```
big_c = Σ_i  λ_i · (x_i · H(pk ‖ app_id) + y_i · app_pk)
      = msk · H(pk ‖ app_id) + (Σ_i λ_i · y_i) · app_pk
```

If participant `j` substitutes `x_j'` for `x_j`, the coordinator computes:

```
big_c_corrupt = (msk − λ_j·x_j + λ_j·x_j') · H(pk ‖ app_id) + (Σ λ_i·y_i) · app_pk
```

After unmasking with `app_sk`:

```
confidential_key_corrupt = big_c_corrupt − app_sk · big_y
                         = (msk − λ_j·x_j + λ_j·x_j') · H(pk ‖ app_id)
```

This is not `msk · H(pk ‖ app_id)`. The coordinator and all honest parties accept this incorrect value as the legitimate CKD output. The impact is **corruption of the CKD output** — honest parties derive and use a wrong confidential key, which is in the allowed impact scope: *High: Corruption of CKD outputs so honest parties accept inconsistent or unusable cryptographic outputs*.

### Likelihood Explanation
Any single participant in the `participants` list can trigger this. No special privilege is required beyond being a listed participant. The attacker only needs to deviate from the honest protocol in `do_ckd_participant` by computing `norm_big_c` with a chosen scalar instead of their real `x_i`. The coordinator has no mechanism to detect or reject this deviation.

### Recommendation
Add a zero-knowledge proof of correct key usage to each participant's contribution, analogous to the proof-of-knowledge used in DKG. Specifically, each participant should prove in zero knowledge that `norm_big_c_i` was formed using the same `x_i` that corresponds to their public verification share. A standard approach is a Chaum-Pedersen DLEQ proof showing that the discrete log of `(norm_big_c_i − λ_i · y_i · app_pk)` with respect to `H(pk ‖ app_id)` equals the discrete log of the participant's public key share with respect to the generator.

### Proof of Concept
1. Honest participants `{1, 2, 3}` run DKG and obtain shares `x_1, x_2, x_3` with master secret `msk = Σ λ_i · x_i`.
2. Participant 1 is malicious. Instead of computing `norm_big_c_1 = λ_1 · (x_1 · H(pk ‖ app_id) + y_1 · app_pk)`, it computes `norm_big_c_1 = λ_1 · (0 · H(pk ‖ app_id) + y_1 · app_pk)` (substituting `x_1' = 0`).
3. Participant 1 sends this forged `(norm_big_y_1, norm_big_c_1)` to the coordinator via `chan.send_private`.
4. The coordinator's `do_ckd_coordinator` calls `recv_from_others`, which only deduplicates by participant identity (via `ParticipantCounter`) but performs no content validation.
5. The coordinator sums all contributions and outputs `ckd_output` where the embedded secret is `msk − λ_1 · x_1` instead of `msk`.
6. All honest parties accept this output. The derived confidential key is permanently wrong for every subsequent use of this `app_id`. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3)

### Citations

**File:** src/confidential_key_derivation/protocol.rs (L29-32)
```rust
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

**File:** src/protocol/helpers.rs (L15-24)
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
```
