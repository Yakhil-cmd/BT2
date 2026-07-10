### Title
Malicious CKD Participant Can Inject Arbitrary Group Elements Without Proof of Correctness, Corrupting the Confidential Key Output - (File: src/confidential_key_derivation/protocol.rs)

---

### Summary

In `do_ckd_coordinator`, the coordinator aggregates `(norm_big_y, norm_big_c)` contributions from every participant by direct addition, with no zero-knowledge proof or any other verification that each participant computed their share correctly from their actual private key share. A single malicious participant can send arbitrary BLS12-381 G1 elements, causing the coordinator to output a corrupted `CKDOutput` that decrypts to a wrong confidential key, permanently denying the requesting application its correct deterministic secret.

---

### Finding Description

The CKD protocol is a two-role protocol: each non-coordinator participant computes and sends `(λi·Yi, λi·Ci)` to the coordinator, and the coordinator sums all contributions.

In `do_ckd_participant` (lines 17–33), a participant computes:

```
y_i  ← random scalar
Y_i  = y_i · G
S_i  = x_i · H(pk ‖ app_id)
C_i  = S_i + y_i · A
sends (λi·Y_i, λi·C_i) to coordinator
```

In `do_ckd_coordinator` (lines 35–58), the coordinator simply accumulates every received pair:

```rust
for (_, participant_output) in
    recv_from_others::<CKDOutput>(&chan, waitpoint, &participants, me).await?
{
    norm_big_y += participant_output.big_y();
    norm_big_c += participant_output.big_c();
}
```

There is **no proof** that the received `big_c` was formed as `λi·(x_i·H(pk‖app_id) + y_i·A)` for the participant's actual key share `x_i`, and **no proof** that `big_y` was formed as `λi·y_i·G` for the same `y_i`. The coordinator accepts and accumulates any group element sent by any participant in the protocol.

The correct final output should satisfy:

```
C − a·Y  =  msk · H(pk ‖ app_id)
```

where `msk = Σ λi·x_i` is the master secret key and `a` is the application's ElGamal secret. If participant `m` sends `(big_y_m*, big_c_m*)` instead of their correct `(λm·y_m·G, λm·C_m)`, the decrypted result becomes:

```
C_final − a·Y_final
  = (Σ_{i≠m} λi·x_i·H) + big_c_m* − a·big_y_m*
  ≠ msk · H(pk ‖ app_id)   (in general)
```

The application receives a wrong key that does not correspond to `msk·H(pk‖app_id)`, and the BLS signature verification step (`verify_signature`) will fail or yield an incorrect secret.

---

### Impact Explanation

**High — Corruption of CKD outputs so honest parties accept unusable cryptographic outputs.**

The coordinator outputs a `CKDOutput` that is accepted as valid by the protocol (no error is raised), but the embedded `(Y, C)` pair decrypts to a wrong value. The application's call to `ckd_output.unmask(app_sk)` returns a wrong BLS point, so the derived confidential key `s = HKDF(sig)` is wrong. The application permanently loses access to its correct deterministic secret for the given `(app_id, A)` pair. Because the protocol is deterministic on the honest side, re-running it with the same inputs will produce the same corrupted output as long as the malicious participant is present.

---

### Likelihood Explanation

Any single participant in the CKD protocol can trigger this. The participant role is reachable by any node that holds a valid key share and is included in the `participants` list passed to `ckd()`. No special privilege beyond being a listed participant is required. The attack requires only that the malicious participant send a crafted message (e.g., the identity element `G1::identity()` for both fields) instead of their correct contribution. This is a one-round, one-message attack with no cryptographic barrier.

---

### Recommendation

Each participant must accompany their `(norm_big_y, norm_big_c)` with a zero-knowledge proof of correct formation. Concretely, the participant must prove in zero knowledge that:

1. `big_y = λi · y_i · G` for some scalar `y_i` (proof of discrete log / knowledge of `y_i`).
2. `big_c = λi · (x_i · H(pk‖app_id) + y_i · A)` for the same `y_i` and for `x_i` consistent with the participant's public verification share `X_i = x_i · G` (a proof of discrete-log equality / Pedersen commitment opening).

The existing `src/crypto/proofs/dlogeq.rs` module already implements a discrete-log equality proof (`Statement`, `prove_with_nonce`, `verify`) that can be adapted for this purpose. The coordinator must verify each participant's proof before adding their contribution to the running sum.

---

### Proof of Concept

**Setup**: 3-participant CKD with threshold 2. Participant `P2` is malicious.

**Honest execution** (from `tests/ckd.rs`):
- All three participants call `ckd(...)` with their correct key shares.
- Coordinator sums contributions; `ckd_output.unmask(app_sk)` equals `msk·H(pk‖app_id)`.
- `verify_signature(&public_key, &app_id, &confidential_key)` succeeds.

**Attack**:
- `P2` intercepts the channel and, instead of sending `(λ2·y2·G, λ2·C2)`, sends `(G1::identity(), G1::identity())` (the additive identity).
- The coordinator at lines 50–55 adds these zero elements without error.
- The final `norm_big_y` and `norm_big_c` are missing `P2`'s contribution.
- `ckd_output.unmask(app_sk)` returns `(λ1·x1 + λ3·x3)·H(pk‖app_id)` instead of `msk·H(pk‖app_id)`.
- `verify_signature` fails, and the application cannot obtain its correct confidential key.

The root cause is at: [1](#0-0) 

with no proof-of-correctness check anywhere in the coordinator aggregation path, and the participant send path at: [2](#0-1) 

The `CKDOutput` structure that carries the unverified elements: [3](#0-2) 

The protocol specification confirms the expected mathematical invariant that is violated: [4](#0-3)

### Citations

**File:** src/confidential_key_derivation/protocol.rs (L27-32)
```rust
    let (norm_big_y, norm_big_c) =
        compute_signature_share(participants, me, key_pair, app_id, app_pk, rng)?;
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

**File:** src/confidential_key_derivation/mod.rs (L32-57)
```rust
pub struct CKDOutput {
    big_y: ElementG1,
    big_c: ElementG1,
}

impl CKDOutput {
    pub fn new(big_y: ElementG1, big_c: ElementG1) -> Self {
        Self { big_y, big_c }
    }

    /// Outputs `big_y`
    pub fn big_y(&self) -> ElementG1 {
        self.big_y
    }

    /// Outputs `big_c`
    pub fn big_c(&self) -> ElementG1 {
        self.big_c
    }

    /// Takes a secret scalar and returns
    /// s <- C − a ⋅ Y = msk ⋅ H ( `app_id` )
    pub fn unmask(&self, secret_scalar: Scalar) -> Signature {
        self.big_c - self.big_y * secret_scalar
    }
}
```

**File:** docs/confidential_key_derivation/confidential-key-derivation.md (L162-175)
```markdown
  - Node $`i`$ sends $`(λ_i \cdot Y_i, λ_i \cdot C_i)`$ to the *MPC network*
    coordinator
  - The coordinator adds the received pairs together:
    - $`Y \gets λ_1 \cdot Y_1 + \ldots + λ_n \cdot Y_n`$
    - $`C \gets λ_1 \cdot C_1 + \ldots + λ_n \cdot C_n = λ_1 \cdot S_1 + \ldots +
    λ_n \cdot S_n + ({y_1 \cdot λ_1 + \ldots + y_n \cdot λ_n }) \cdot A =
    \texttt{msk} \cdot H(\texttt{pk},\, \texttt{app\_id}) + a \cdot Y`$
    - $`\texttt{es} \gets (Y, C) `$
  - Coordinator sends $`\texttt{es}`$ to *app* on-chain
- *app* obtains $`\texttt{es} = (Y, C)`$ and computes the BLS signature
  $`\texttt{sig} \gets C + (- a) \cdot  Y`$ and checks its correctness with
  respect to the MPC network public key $`\texttt{pk}`$. If correct, the app can
  use the computed $`\texttt{sig} = \texttt{msk} \cdot H(\texttt{pk},\, \texttt{app\_id})`$ to
  compute the key $`s = \texttt{HKDF}(\texttt{sig})`$, using a
```
