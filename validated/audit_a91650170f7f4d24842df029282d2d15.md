### Title
Missing Proof of Correctness for Participant Contributions in CKD Protocol Allows Malicious Participant to Corrupt Confidential Derived Key Output - (File: src/confidential_key_derivation/protocol.rs)

### Summary
The CKD coordinator in `do_ckd_coordinator` blindly sums up `(big_y, big_c)` group-element contributions received from every participant with no proof that each contribution is well-formed. This is the direct analog of the Balancer `batchSwap` with infinite limits: just as that function accepts any exchange rate, the CKD coordinator accepts any arbitrary elliptic-curve points from any participant. A single malicious participant can therefore corrupt the final `CKDOutput` that all honest parties accept, causing the app to derive an incorrect confidential key.

### Finding Description

**Protocol background.** Each participant is supposed to contribute:

```
norm_big_y_i = lambda_i * y_i * G          (randomized ephemeral public key)
norm_big_c_i = lambda_i * (x_i * H + y_i * A)   (randomized ElGamal ciphertext share)
```

where `x_i` is the participant's secret signing share, `y_i` is a fresh random scalar, `H = hash_app_id_with_pk(pk, app_id)`, and `A = app_pk`.

**Root cause.** In `do_ckd_coordinator` the coordinator simply accumulates whatever it receives:

```rust
// src/confidential_key_derivation/protocol.rs  lines 50-55
for (_, participant_output) in
    recv_from_others::<CKDOutput>(&chan, waitpoint, &participants, me).await?
{
    norm_big_y += participant_output.big_y();
    norm_big_c += participant_output.big_c();
}
```

There is no zero-knowledge proof, commitment scheme, or any other check that:
1. `big_y_i` is `lambda_i * y_i * G` for some scalar `y_i` the participant actually knows.
2. `big_c_i` uses the **same** `y_i` as `big_y_i`.
3. `big_c_i` encodes the participant's **legitimate** secret share `x_i` (not an arbitrary value).

Compare this with the triple-generation protocol in `src/ecdsa/ot_based_ecdsa/triples/generation.rs` (lines 365–389), which requires discrete-log proofs (`dlog::verify`) for every received polynomial commitment before accepting it. The CKD protocol has no equivalent guard.

**Exploit path.**
1. A malicious participant `P_m` participates in a legitimate CKD session.
2. Instead of computing the honest `(norm_big_y_m, norm_big_c_m)`, `P_m` sends arbitrary group elements, e.g. `(G, G)` or the identity `(O, O)`.
3. The coordinator sums all contributions including the malicious ones and outputs the corrupted `CKDOutput`.
4. All honest parties (including the coordinator) accept this output as the result of the protocol.
5. When the app later calls `ckd_output.unmask(app_sk)` it decrypts a value that is **not** `msk * H(pk, app_id)`.

### Impact Explanation

**High – Corruption of CKD outputs so honest parties accept an unusable or inconsistent confidential derived key.**

The final `CKDOutput = (Y, C)` is corrupted. The app decrypts:

```
C' - x_app * Y'  ≠  msk * H(pk, app_id)
```

Honest parties have no mechanism to detect the corruption; they receive a single `CKDOutput` from the coordinator and use it directly. Any downstream system relying on the derived key (e.g., a TEE that uses it to decrypt secrets) will silently operate on a wrong key. The malicious participant needs no privileged access beyond being a valid member of the participant list.

### Likelihood Explanation

Any one of the `n` participants in a CKD session can trigger this. The attacker needs only to be a registered participant (no key theft, no external oracle). The attack is a single-round deviation: send crafted group elements instead of the honest contribution. It is undetectable by the coordinator or any other honest party because no proof of correctness is required or checked.

### Recommendation

Add a Sigma/Maurer proof of correct encryption to each participant's contribution, analogous to the `dlog` and `dlogeq` proofs already used in triple generation. Specifically, each participant should prove:

1. **Knowledge of `y_i`**: `big_y_i = lambda_i * y_i * G` — a standard discrete-log proof (`dlog`).
2. **Correct ciphertext**: `big_c_i = lambda_i * x_i * H + lambda_i * y_i * A` using the **same** `y_i` — a discrete-log equality proof (`dlogeq`) binding `big_y_i` and `big_c_i` to the same randomness.
3. **Correct secret share**: `big_c_i` encodes the participant's committed share `x_i` (verifiable against the public key package from DKG).

The coordinator must verify all three proofs before accumulating any contribution, and abort if any proof fails.

### Proof of Concept

```
Setup: 3 participants P1, P2, P3 (threshold 2). P3 is malicious.

1. P1 and P2 compute honest (norm_big_y_i, norm_big_c_i) as per compute_signature_share().
2. P3 sends (G, G) — the generator point for both fields — instead of its honest contribution.
3. Coordinator accumulates:
     Y_final  = lambda_1*y_1*G + lambda_2*y_2*G + G          (corrupted)
     C_final  = lambda_1*(x_1*H+y_1*A) + lambda_2*(x_2*H+y_2*A) + G  (corrupted)
4. app.unmask(app_sk) computes C_final - app_sk * Y_final
   = (x_1*lambda_1 + x_2*lambda_2)*H + (lambda_1*y_1+lambda_2*y_2)*(A - app_sk*G) + G - app_sk*G
   ≠ msk * H(pk, app_id)
5. The honest parties accept and use this wrong key with no error.
```

The deviation at step 2 is undetectable because `do_ckd_coordinator` performs no proof verification on received `CKDOutput` values.