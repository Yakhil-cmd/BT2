### Title
Unverified Participant Shares in CKD Coordinator Allow Malicious Participant to Corrupt Derived Confidential Key - (File: `src/confidential_key_derivation/protocol.rs`)

### Summary
The CKD coordinator in `do_ckd_coordinator` blindly sums received `(big_y, big_c)` share pairs from all participants without any cryptographic verification of their correctness. A single malicious participant can send arbitrary elliptic-curve points, causing the coordinator to output a corrupted `CKDOutput` that does not correspond to the honest parties' shared secret key.

### Finding Description
In `do_ckd_coordinator`, the coordinator collects each participant's `CKDOutput` and accumulates it directly: [1](#0-0) 

Each participant is supposed to send `(norm_big_y, norm_big_c)` computed as:

- `big_y = y_i * G` (random blinding point)
- `big_s = x_i * H(pk || app_id)` (secret share contribution)
- `big_c = big_s + y_i * app_pk` (ElGamal-masked contribution)
- Both multiplied by the Lagrange coefficient `lambda_i` [2](#0-1) 

There is no NIZK proof, commitment, or any other check that the received `big_y` and `big_c` are correctly formed relative to the participant's committed public key share. The coordinator has no mechanism to detect a deviation.

Compare this to the DKG protocol, which enforces correctness of every participant contribution via proof-of-knowledge verification and commitment hashing before accepting any share: [3](#0-2) 

No equivalent verification exists in the CKD path.

### Impact Explanation
The final `CKDOutput` is the sum of all participant contributions. If one participant sends a crafted `(big_y_evil, big_c_evil)` pair, the coordinator outputs:

```
big_Y_out = big_Y_honest + big_y_evil
big_C_out = big_C_honest + big_c_evil
```

The TEE that later calls `unmask(app_sk)` computes `big_C_out - app_sk * big_Y_out`, which will not equal `msk * H(pk || app_id)`. The derived confidential key is silently wrong. Honest parties have no way to detect this; they accept and use the corrupted output.

This matches: **High — Corruption of CKD outputs so honest parties accept unusable cryptographic outputs.**

### Likelihood Explanation
Any single participant in the CKD protocol can execute this attack. No special privilege is required beyond being a valid participant. The attack requires only sending two arbitrary group elements instead of the honest computation — a trivial deviation for a malicious library caller or compromised node. The threshold structure provides no protection here because the coordinator aggregates all `n` shares unconditionally.

### Recommendation
Each participant should accompany their `(norm_big_y, norm_big_c)` with a NIZK proof of correct formation. Concretely, a proof of discrete-log equality (a `dlogeq` proof, which the library already implements in `src/crypto/proofs/dlogeq.rs`) can prove that `big_c - big_y_unnorm * app_pk` lies on the same discrete-log relation as the participant's public verification share times `H(pk || app_id)`. The coordinator must verify this proof before incorporating any share into the sum. [4](#0-3) 

### Proof of Concept

1. Honest setup: run DKG to obtain `(private_share_i, public_key)` for each participant.
2. Malicious participant `P_evil` intercepts the CKD round and, instead of computing the honest `(norm_big_y, norm_big_c)`, sends `(G, G)` (the generator point for both fields).
3. The coordinator executes:

```rust
// do_ckd_coordinator — no verification branch
for (_, participant_output) in recv_from_others(...).await? {
    norm_big_y += participant_output.big_y();  // adds G unconditionally
    norm_big_c += participant_output.big_c();  // adds G unconditionally
}
let ckd_output = CKDOutput::new(norm_big_y, norm_big_c);
Ok(Some(ckd_output))
```

4. The coordinator returns `Some(ckd_output)` with no error.
5. The TEE calls `ckd_output.unmask(app_sk)` and obtains a value that is not `msk * H(pk || app_id)`.
6. The derived confidential key is silently corrupted; all downstream operations using it produce wrong results. [5](#0-4)

### Citations

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

**File:** src/dkg.rs (L452-469)
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

        // verify that the commitment sent hashes to the received commitment_hash in round 1
        verify_commitment_hash(
            &session_id,
            p,
            &mut commit_domain_separator.clone(), // you want to have the same state
            commitment_i,
            &all_hash_commitments,
        )?;
```

**File:** src/crypto/proofs/dlogeq.rs (L1-5)
```rust
use super::strobe_transcript::Transcript;
use crate::{
    crypto::constants::{
        NEAR_DLOGEQ_CHALLENGE_LABEL, NEAR_DLOGEQ_COMMITMENT_LABEL,
        NEAR_DLOGEQ_ENCODE_LABEL_GENERATOR1, NEAR_DLOGEQ_ENCODE_LABEL_PUBLIC0,
```
