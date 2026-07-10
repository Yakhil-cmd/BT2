### Title
Swapped Sign of Secret Input `a` in MTA Sender Corrupts Beaver Triple Generation — (`File: src/ecdsa/ot_based_ecdsa/triples/mta.rs`)

### Summary

The `mta_sender` function in the OT-based ECDSA triple generation sends the wrong sign for the secret input `a` in both elements of the correlated pair. The code uses `+a` where the protocol specification requires `-a`, and `-a` where the spec requires `+a`. This is a direct analog of the external report's pattern: using the wrong variable/value in a critical calculation, causing the MTA sub-protocol to compute `-a·b` instead of `a·b`, which corrupts every Beaver triple produced by the OT-based ECDSA presigning path.

---

### Finding Description

The MTA (Multiplicative-to-Additive) protocol is documented in `docs/ecdsa/ot_based_ecdsa/triples.md`. Step 2 of the protocol specifies that the sender must transmit:

$$(-a + \delta_i + v_i^0,\quad a + \delta_i + v_i^1)$$ [1](#0-0) 

The production implementation in `mta_sender` instead sends:

```rust
(
    SerializableScalar(*v0_i + delta_i + a),   // should be: -a + delta_i + v0_i
    SerializableScalar(*v1_i + delta_i - a),   // should be:  a + delta_i + v1_i
)
``` [2](#0-1) 

The sign of `a` is swapped in both elements relative to the specification. The receiver then computes `m_i = c^{t_i}_i - v_i^{t_i}` per the spec:

- When `t_i = 0`: receiver gets `(v0_i + δ_i + a) − v0_i = δ_i + a` (spec: `δ_i − a`)
- When `t_i = 1`: receiver gets `(v1_i + δ_i − a) − v1_i = δ_i − a` (spec: `δ_i + a`)

This is equivalent to negating `a` throughout the protocol, so the MTA outputs satisfy `α + β = −a·b` instead of the required `α + β = a·b`. Every Beaver triple `(a, b, c)` produced by the triple generation protocol will have `c = −a·b` rather than `c = a·b`.

The sender's final output is computed as `-alpha` over the `delta` values: [3](#0-2) 

---

### Impact Explanation

Beaver triples with `c = −a·b` are structurally incorrect. When the OT-based ECDSA presigning protocol uses these triples to blind and unmask the product of two secret nonce shares, the unmasking step will produce a value off by a negation. The resulting presignature components (`k`, `sigma`) will be inconsistent with the public nonce commitment `big_r`, causing every subsequent signing attempt to produce an invalid ECDSA signature that fails verification. Honest parties will accept these presignatures as their own output (no local check catches the triple incorrectness), but the signatures will be unusable.

This matches: **High — Corruption of presign outputs so honest parties accept unusable cryptographic outputs.**

---

### Likelihood Explanation

The bug is triggered unconditionally on every execution of the OT-based ECDSA presigning path. No adversarial input is required; any two honest participants running `mta_sender` / `mta_receiver` will produce corrupted triples. The triple generation is a mandatory offline phase before any OT-based ECDSA signature can be produced, so the denial of signing is permanent for this scheme variant under all valid inputs.

---

### Recommendation

Correct the sign of `a` in both tuple elements to match the protocol specification:

```rust
// Step 2 — corrected
let c: MTAScalars = MTAScalars(
    delta
        .iter()
        .zip(v.iter())
        .map(|(delta_i, (v0_i, v1_i))| {
            (
                SerializableScalar(*v0_i + delta_i - a),  // was: + a
                SerializableScalar(*v1_i + delta_i + a),  // was: - a
            )
        })
        .collect(),
);
```

Add a unit test that verifies `α + β = a·b` for known inputs to the MTA sender/receiver pair, independent of the snapshot tests.

---

### Proof of Concept

Let `a = 3`, `b = 5` (conceptually over the scalar field), `δ_i = 7`, `v0_i = v1_i = 0`, and suppose the receiver's bit `t_i = 1`.

**With the buggy code:**
- Sender transmits `c^1_i = v1_i + δ_i − a = 0 + 7 − 3 = 4`
- Receiver computes `m_i = c^1_i − v1_i = 4 − 0 = 4 = δ_i − a` ✗ (should be `δ_i + a = 10`)

**With the correct code:**
- Sender transmits `c^1_i = v1_i + δ_i + a = 0 + 7 + 3 = 10`
- Receiver computes `m_i = c^1_i − v1_i = 10 − 0 = 10 = δ_i + a` ✓

The receiver's contribution to `β` is built from `m_i − δ_i`, which equals `−a` in the buggy case and `+a` in the correct case. Summed over all bits of `b`, the protocol computes `α + β = −a·b` instead of `a·b`, corrupting the triple. [4](#0-3)

### Citations

**File:** docs/ecdsa/ot_based_ecdsa/triples.md (L206-208)
```markdown
1. $\mathcal{S}$ samples random $\delta_1, \ldots, \delta_\kappa \xleftarrow{R} \mathbb{F}_q$.
2. $\star$ $\mathcal{S}$ sends $(-a + \delta_i + v_i^0, a + \delta_i + v_i^1)$ to $\mathcal{R}$.
3. $\bullet$ $\mathcal{R}$ waits to receive $(c^0_i, c^1_i)$ from $\mathcal{S}$, and
```

**File:** src/ecdsa/ot_based_ecdsa/triples/mta.rs (L36-75)
```rust
/// The sender for multiplicative to additive conversion.
pub async fn mta_sender(
    mut chan: PrivateChannel,
    v: Vec<(Scalar, Scalar)>,
    a: Scalar,
    delta: Vec<Scalar>,
) -> Result<Scalar, ProtocolError> {
    // Step 1
    // `delta` is computed in `mta_sender_random_helper`

    // Step 2
    let c: MTAScalars = MTAScalars(
        delta
            .iter()
            .zip(v.iter())
            .map(|(delta_i, (v0_i, v1_i))| {
                (
                    SerializableScalar(*v0_i + delta_i + a),
                    SerializableScalar(*v1_i + delta_i - a),
                )
            })
            .collect(),
    );
    let wait0 = chan.next_waitpoint();
    chan.send(wait0, &c)?;

    // Step 7
    let wait1 = chan.next_waitpoint();
    let (chi1, seed): (SerializableScalar<Secp256>, [u8; 32]) = chan.recv(wait1).await?;

    let mut alpha = delta[0] * chi1.0;

    let mut prng = TranscriptRng::new(&seed);
    for &delta_i in &delta[1..] {
        let chi_i =
            <<Secp256 as frost_core::Ciphersuite>::Group as Group>::Field::random(&mut prng);
        alpha += delta_i * chi_i;
    }

    Ok(-alpha)
```
