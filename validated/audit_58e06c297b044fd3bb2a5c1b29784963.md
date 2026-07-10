### Title
Unvalidated Participant Contributions in CKD Coordinator Allow Output Corruption - (File: `src/confidential_key_derivation/protocol.rs`)

### Summary
The `do_ckd_coordinator` function in `src/confidential_key_derivation/protocol.rs` receives `CKDOutput` values from all participants and directly accumulates them into the final output without any proof of correctness or consistency check. A single malicious participant can send arbitrary `big_y` and `big_c` group elements, corrupting the coordinator's final `CKDOutput` and causing every honest party to accept a wrong, unusable derived confidential key. This is the direct analog of the Chainlink stale-price pattern: data is received from an external source and consumed without validation.

### Finding Description

**Root cause — no proof of correct computation:**

In `do_ckd_coordinator` the coordinator loops over every participant's reply and blindly adds the two group elements it receives:

```rust
// src/confidential_key_derivation/protocol.rs  lines 50-55
for (_, participant_output) in
    recv_from_others::<CKDOutput>(&chan, waitpoint, &participants, me).await?
{
    norm_big_y += participant_output.big_y();
    norm_big_c += participant_output.big_c();
}
``` [1](#0-0) 

There is no zero-knowledge proof, no consistency check, and no threshold-based reconstruction that would let honest parties detect or discard a malformed contribution. The protocol simply trusts every received `(big_y, big_c)` pair.

**What a correct contribution looks like:**

Each honest participant `i` computes:

```rust
// src/confidential_key_derivation/protocol.rs  lines 165-180
let big_y = ElementG1::generator() * y.0;          // y_i * G
let big_s = hash_point * private_share.to_scalar(); // x_i * H(pk, app_id)
let big_c = big_s + app_pk * y.0;                  // x_i*H + y_i*A
let lambda_i = participants.lagrange::<BLS12381SHA256>(me)?;
let norm_big_y = big_y * lambda_i;
let norm_big_c = big_c * lambda_i;
``` [2](#0-1) 

The coordinator then sums these to reconstruct `msk * H(pk, app_id) + Y * app_sk`. Nothing in the protocol binds the received `(norm_big_y, norm_big_c)` to the participant's public key share or to the agreed `app_id` / `app_pk`.

**Exploit flow:**

1. A malicious participant `j` participates in the CKD protocol.
2. Instead of sending the correctly computed `(norm_big_y_j, norm_big_c_j)`, it sends arbitrary group elements `(G', C')` — e.g., the identity element for both, or any crafted point.
3. The coordinator accumulates these without complaint:
   - `final_big_Y = Σ_{i≠j} norm_big_y_i + G'`
   - `final_big_C = Σ_{i≠j} norm_big_c_i + C'`
4. The resulting `CKDOutput` is returned to the caller. The TEE application unmasks it as `final_big_C − app_sk * final_big_Y`, which is no longer equal to `msk * H(pk, app_id)`.
5. Every honest party that relies on this output receives a wrong confidential key with no indication of failure.

The participant function sends its share privately to the coordinator with no attached proof:

```rust
// src/confidential_key_derivation/protocol.rs  lines 29-32
let waitpoint = chan.next_waitpoint();
chan.send_private(waitpoint, coordinator, &(norm_big_y, norm_big_c))?;
Ok(None)
``` [3](#0-2) 

### Impact Explanation

A single malicious participant (no special privilege required beyond being in the participant list) can corrupt the `CKDOutput` produced by the coordinator. The derived confidential key delivered to the TEE application will be wrong. Because the protocol produces no error and no honest party can detect the manipulation, the corruption is silent and permanent for that invocation. This matches the allowed High impact: **Corruption of CKD outputs so honest parties accept unusable cryptographic outputs**.

### Likelihood Explanation

Any participant in the CKD session is a sufficient attacker. The participant list is caller-supplied and can include an adversary. No cryptographic capability beyond participation is required. The attack requires sending two arbitrary group elements instead of the correct ones — trivially achievable by any participant who controls their own process. Likelihood is **High**.

### Recommendation

Require each participant to attach a zero-knowledge proof of correct computation alongside `(norm_big_y, norm_big_c)`. Concretely, the participant should prove in zero knowledge that:

- `norm_big_y = lambda_i * y_i * G` for some `y_i` (discrete-log proof on `G`), and
- `norm_big_c = lambda_i * (x_i * H(pk, app_id) + y_i * app_pk)` is consistent with the participant's public key share `X_i = x_i * G2` and the agreed `app_pk` (a dlog-equality / Pedersen-consistency proof).

The coordinator must verify all proofs before accumulating any contribution and abort if any proof fails. This is the same pattern already used in the DKG (`verify_proof_of_knowledge`, `validate_received_share`) and in the OT-based ECDSA triple generation (`dlogeq::verify`).

### Proof of Concept

```
Setup: 3 participants P1, P2, P3 (coordinator = P1). Threshold = 3.
       Honest: P1, P2. Malicious: P3.

Step 1 – P3 computes its correct share but instead sends:
         big_y  = ElementG1::identity()   // zero contribution to Y
         big_c  = ElementG1::identity()   // zero contribution to C

Step 2 – Coordinator (P1) receives and accumulates:
         norm_big_Y = norm_big_y_P1 + norm_big_y_P2 + identity
         norm_big_C = norm_big_c_P1 + norm_big_c_P2 + identity
         (P3's Lagrange-weighted secret share is missing from the sum)

Step 3 – CKDOutput { big_y: norm_big_Y, big_c: norm_big_C } is returned.

Step 4 – TEE app unmasks: norm_big_C − app_sk * norm_big_Y
         = (λ1*x1 + λ2*x2)*H(pk,app_id) + (λ1*y1+λ2*y2)*app_pk
           − app_sk*(λ1*y1+λ2*y2)*G
         = (λ1*x1 + λ2*x2)*H(pk,app_id)
         ≠ msk*H(pk,app_id)   [since msk = λ1*x1+λ2*x2+λ3*x3]

Result: The derived confidential key is wrong. No error is raised.
        Repeating the protocol with the same inputs yields the same
        corrupted key as long as P3 continues to misbehave.
```

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
