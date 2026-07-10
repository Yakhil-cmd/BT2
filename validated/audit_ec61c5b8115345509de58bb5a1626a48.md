### Title
Missing Validation of Participant Contributions in CKD Protocol Allows Output Corruption - (File: src/confidential_key_derivation/protocol.rs)

### Summary
The CKD coordinator aggregates `(norm_big_y, norm_big_c)` values received from participants with no proof of correct computation and no consistency check against each participant's committed key share. A single malicious participant can send arbitrary group elements, causing the coordinator to output a corrupted `CKDOutput` that honest parties will accept as valid, permanently breaking the derived key for the targeted `app_id`.

### Finding Description

In `do_ckd_coordinator`, the coordinator receives each participant's `CKDOutput` and unconditionally adds the two group elements together:

```rust
for (_, participant_output) in
    recv_from_others::<CKDOutput>(&chan, waitpoint, &participants, me).await?
{
    norm_big_y += participant_output.big_y();
    norm_big_c += participant_output.big_c();
}
``` [1](#0-0) 

The honest computation each participant is supposed to perform is:

```
big_y  = y_i * G
big_s  = x_i * H(pk || app_id)
big_c  = big_s + y_i * app_pk
norm_big_y = lambda_i * big_y
norm_big_c = lambda_i * big_c
``` [2](#0-1) 

There is no zero-knowledge proof, no commitment binding, and no consistency check that the received `big_c` was formed using the participant's actual private share `x_i` and the same `y_i` used for `big_y`. The `CKDOutput` constructor performs no validation either: [3](#0-2) 

Participants send their contribution privately to the coordinator only (not via broadcast), so no other honest participant can observe or challenge the malicious value: [4](#0-3) 

The coordinator then returns the corrupted `CKDOutput` as `Some(ckd_output)`, which the caller treats as a valid result: [5](#0-4) 

### Impact Explanation

The final `CKDOutput` is used by the client to unmask the derived key via `C - a*Y = msk * H(pk, app_id)`. If a malicious participant substitutes arbitrary `(big_y, big_c)` values, the sum `(Y_total, C_total)` is poisoned, and `unmask` returns a value that is not `msk * H(pk, app_id)`. The derived key is permanently wrong for that `(pk, app_id)` pair. This matches the allowed High impact: **Corruption of CKD outputs so honest parties accept unusable cryptographic outputs**.

### Likelihood Explanation

Any single participant in the CKD protocol can trigger this. The attacker needs only to be a legitimate participant (no special privilege beyond holding a key share). The private channel to the coordinator means the deviation is undetectable by other participants. The attack is deterministic and requires no cryptographic break.

### Recommendation

Add a non-interactive proof of correct computation alongside each participant's `(norm_big_y, norm_big_c)` contribution. Concretely, each participant should prove in zero knowledge that:
- `norm_big_y = lambda_i * y_i * G` for some `y_i`
- `norm_big_c = lambda_i * (x_i * H(pk||app_id) + y_i * app_pk)` using the same `x_i` committed during DKG and the same `y_i`

This is a standard DLEQ-style proof (the codebase already implements `dlogeq` proofs in `src/crypto/proofs/dlogeq.rs`) and would allow the coordinator to reject any malformed contribution before aggregation.

### Proof of Concept

1. Run CKD with 3 participants, threshold 2, coordinator = P1.
2. Malicious participant P2 intercepts the protocol at `do_ckd_participant` and instead of computing the honest `(norm_big_y, norm_big_c)`, sends `(ElementG1::identity(), ElementG1::identity())` (or any arbitrary point).
3. The coordinator at line 53–54 adds these values without any check.
4. The resulting `CKDOutput` has `big_y` and `big_c` shifted by the malicious delta.
5. The client calls `ckd_output.unmask(app_sk)` and receives a value ≠ `msk * H(pk, app_id)`.
6. The derived key is permanently corrupted for this `(pk, app_id)` pair; no honest retry can recover it without re-running the protocol with a different participant set.

### Citations

**File:** src/confidential_key_derivation/protocol.rs (L29-32)
```rust
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

**File:** src/confidential_key_derivation/protocol.rs (L56-57)
```rust
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

**File:** src/confidential_key_derivation/mod.rs (L38-40)
```rust
    pub fn new(big_y: ElementG1, big_c: ElementG1) -> Self {
        Self { big_y, big_c }
    }
```
