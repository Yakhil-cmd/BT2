### Title
Malicious Participant Can Corrupt CKD Output by Injecting Unvalidated Arbitrary Group Elements — (File: src/confidential_key_derivation/protocol.rs)

---

### Summary

The CKD coordinator in `do_ckd_coordinator` accumulates each participant's contribution `(norm_big_y, norm_big_c)` by simple addition with no proof of correctness, commitment binding, or pairing-based consistency check. A single malicious participant can substitute arbitrary BLS12-381 group elements for their honest share, causing the coordinator to output a corrupted encrypted key. The TEE that decrypts the output receives a value that is not `msk · H(pk, app_id)`, permanently corrupting the CKD result for that session.

---

### Finding Description

**Root cause — implicit accumulation without validation**

In `do_ckd_coordinator` the coordinator computes its own share and then unconditionally sums every received pair:

```rust
// src/confidential_key_derivation/protocol.rs  lines 44-57
async fn do_ckd_coordinator(...) -> Result<CKDOutputOption, ProtocolError> {
    let (mut norm_big_y, mut norm_big_c) =
        compute_signature_share(&participants, me, key_pair, app_id, app_pk, rng)?;

    let waitpoint = chan.next_waitpoint();

    for (_, participant_output) in
        recv_from_others::<CKDOutput>(&chan, waitpoint, &participants, me).await?
    {
        norm_big_y += participant_output.big_y();   // ← no validation
        norm_big_c += participant_output.big_c();   // ← no validation
    }
    let ckd_output = CKDOutput::new(norm_big_y, norm_big_c);
    Ok(Some(ckd_output))
}
```

The honest computation each participant is supposed to perform is:

```rust
// src/confidential_key_derivation/protocol.rs  lines 148-181
let big_y  = G1::generator() * y_i;
let big_s  = H(pk, app_id) * x_i;          // x_i = private share
let big_c  = big_s + app_pk * y_i;
let norm_big_y = big_y * lambda_i;
let norm_big_c = big_c * lambda_i;
```

A malicious participant instead sends `(Δ_Y, Δ_C)` — arbitrary G1 elements — via `do_ckd_participant`, which performs no proof of knowledge and simply forwards whatever it computes (or whatever an attacker substitutes):

```rust
// src/confidential_key_derivation/protocol.rs  lines 17-33
fn do_ckd_participant(...) -> Result<CKDOutputOption, ProtocolError> {
    let (norm_big_y, norm_big_c) =
        compute_signature_share(participants, me, key_pair, app_id, app_pk, rng)?;
    let waitpoint = chan.next_waitpoint();
    chan.send_private(waitpoint, coordinator, &(norm_big_y, norm_big_c))?;
    Ok(None)
}
```

No proof of knowledge is attached; the coordinator has no way to distinguish a correct share from an arbitrary group element.

**Exploit arithmetic**

Let honest aggregate be `(Y_h, C_h)` where `C_h − app_sk · Y_h = msk · H(pk, app_id)`.  
Malicious participant sends `(Δ_Y, Δ_C)` instead of their correct share.  
Coordinator outputs `Y_out = Y_h + Δ_Y`, `C_out = C_h + Δ_C`.  
TEE decrypts: `C_out − app_sk · Y_out = msk · H(pk, app_id) + Δ_C − app_sk · Δ_Y`.

Unless `Δ_C = app_sk · Δ_Y` (which requires knowing `app_sk`), the decrypted key is wrong. The attacker does not need to know `app_sk` to corrupt the output; they only need to send any `(Δ_Y, Δ_C) ≠ (norm_big_y_correct, norm_big_c_correct)`.

**Contrast with DKG**

The DKG protocol validates every received share against a polynomial commitment before accumulating it (`validate_received_share`, `src/dkg.rs` lines 259–285). The CKD protocol performs no analogous check.

---

### Impact Explanation

A malicious participant causes the coordinator to output a CKD ciphertext that decrypts to an attacker-influenced value instead of `msk · H(pk, app_id)`. The TEE receives and uses a wrong derived key. This is a concrete, permanent corruption of a CKD output for the affected session.

**Mapped impact**: High — Corruption of CKD outputs so honest parties accept unusable cryptographic outputs.

---

### Likelihood Explanation

Any participant in the CKD protocol can execute this attack with no special privileges. The participant role is reachable by any node that holds a valid key share (obtained through the public DKG). The attack requires only sending two arbitrary G1 points instead of the correct values — a trivial code modification. In a decentralized MPC network with even one compromised or malicious node, this attack is immediately reachable.

---

### Recommendation

Add a pairing-based consistency check on each received contribution before accumulating it. Because the coordinator holds the master verification key `pk = msk · G2` and each participant's Lagrange-weighted public key share `lambda_i · pk_i` can be derived from the DKG output, the coordinator can verify:

```
e(norm_big_c, G2) == e(H(pk, app_id), lambda_i · pk_i) · e(app_pk, norm_big_y)
```

This check is zero-knowledge with respect to `x_i` and `y_i` and can be performed using the BLS12-381 pairing already available in the ciphersuite. Alternatively, require each participant to attach a Schnorr proof of knowledge of `y_i` alongside `(norm_big_y, norm_big_c)`, analogous to the proof-of-knowledge check enforced in the DKG (`src/dkg.rs` lines 118–141, 143–166).

---

### Proof of Concept

```
Setup: 3 participants (threshold 2), one malicious (participant P_bad).
       Coordinator = P_coord (honest).

Step 1: P_bad receives the CKD call with valid key_pair, app_id, app_pk.
Step 2: P_bad ignores compute_signature_share() and instead sends:
          norm_big_y' = G1::generator()   // arbitrary non-zero point
          norm_big_c' = G1::generator()   // arbitrary non-zero point
        to the coordinator via send_private().

Step 3: Coordinator executes do_ckd_coordinator():
          norm_big_y += G1::generator()   // corrupted
          norm_big_c += G1::generator()   // corrupted

Step 4: Coordinator outputs CKDOutput::new(Y_out, C_out).

Step 5: TEE calls ckd_output.unmask(app_sk):
          result = C_out - app_sk * Y_out
                 = msk·H(pk,app_id) + G1 - app_sk·G1
                 = msk·H(pk,app_id) + (1 - app_sk)·G1
          ≠ msk·H(pk,app_id)

Expected: msk·H(pk,app_id)
Actual:   msk·H(pk,app_id) + (1 - app_sk)·G1  [corrupted]
```

The CKD output is permanently wrong for this session. No honest party can detect or recover from the corruption without an external verification mechanism that the library explicitly states is not implemented.