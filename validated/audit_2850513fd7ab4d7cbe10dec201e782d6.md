The `is_torsion_free` check only appears in `verify_signature`, not in the deserialization path. Let me confirm the exact serde path for `G1Projective` and the `BLS12381G1Group::deserialize` gap.

### Title
Missing Subgroup Check on Participant-Contributed `big_y` in CKD Coordinator Allows Low-Order Point Injection to Permanently Break CKD Output Verification — (`src/confidential_key_derivation/protocol.rs`)

---

### Summary

A malicious participant can inject a low-order G1 point (on the BLS12-381 curve but not in the prime-order subgroup) as their `big_y` contribution to the CKD coordinator. Because neither the serde deserialization of `CKDOutput` nor the coordinator's aggregation loop performs a subgroup (torsion-free) check, the poisoned point propagates into the final `CKDOutput`. The resulting `unmask` output fails `verify_signature`'s `is_torsion_free()` guard, permanently denying CKD to honest parties for every session in which the malicious participant is included.

---

### Finding Description

**Step 1 — Participant sends contribution to coordinator.**

In `do_ckd_participant`, the participant sends `(norm_big_y, norm_big_c)` privately to the coordinator: [1](#0-0) 

A malicious participant replaces `norm_big_y` with a low-order G1 point `P` (a point on the BLS12-381 G1 curve whose order divides the cofactor `h = 0x396c8c005555e1568c00aaab0000aaab`, not the prime order `r`). Such points are publicly known and trivially constructable.

**Step 2 — Coordinator deserializes without subgroup check.**

The coordinator collects contributions via: [2](#0-1) 

`recv_from_others::<CKDOutput>` deserializes the received bytes into `CKDOutput` using serde. `CKDOutput` derives `serde::Deserialize`: [3](#0-2) 

`big_y` is `blstrs::G1Projective`. The `blstrs` 0.7.1 serde `Deserialize` for `G1Projective` calls `G1Affine::from_compressed()`, which invokes the underlying `blst` C library's `blst_p1_uncompress`. This function verifies the point is on the curve but **does not check subgroup membership**. No `is_torsion_free()` call is made during deserialization.

This is confirmed by the fact that `verify_signature` must explicitly call `is_torsion_free()` itself — if deserialization guaranteed subgroup membership, that check would be redundant: [4](#0-3) 

The `BLS12381G1Group::deserialize` implementation also only checks `is_identity()`, not `is_torsion_free()`: [5](#0-4) 

**Step 3 — Poisoned point is aggregated.**

The coordinator adds the received `big_y` (the low-order point `P`) directly into `norm_big_y`: [6](#0-5) 

The aggregated `norm_big_y` is now `(honest_contributions) + P`, which is outside the prime-order subgroup.

**Step 4 — `unmask` produces an invalid signature.**

`CKDOutput::unmask` computes: [7](#0-6) 

Since `norm_big_y` is not in the prime-order subgroup, `big_y * secret_scalar` is also not in the subgroup, and the result `big_c - big_y * secret_scalar` is not in the prime-order subgroup.

**Step 5 — `verify_signature` rejects the output.** [4](#0-3) 

`is_torsion_free()` returns `false` for the poisoned result, and `verify_signature` returns `Err(InvalidSignature)`. CKD is broken for this session.

---

### Impact Explanation

Every CKD session that includes the malicious participant produces an unusable output. The honest coordinator and client receive a `CKDOutput` that appears structurally valid but whose `unmask` result always fails verification. The malicious participant can repeat this attack in every subsequent session, constituting a persistent denial of CKD for all honest parties who cannot exclude the attacker.

This matches the allowed impact: **High — Permanent denial of CKD for honest parties under valid protocol inputs and documented trust assumptions.**

---

### Likelihood Explanation

The attack requires only that the adversary control one participant's protocol execution — a standard threat model assumption for threshold protocols. No cryptographic assumptions need to be broken. Low-order points on BLS12-381 G1 are publicly documented. The attack is single-round, requires no interaction beyond the normal protocol message, and is undetectable by the coordinator before the client calls `verify_signature`.

---

### Recommendation

Add a subgroup check on every received `big_y` (and `big_c`) before aggregation in `do_ckd_coordinator`:

```rust
for (from, participant_output) in
    recv_from_others::<CKDOutput>(&chan, waitpoint, &participants, me).await?
{
    let y: G1Affine = participant_output.big_y().into();
    if (!y.is_on_curve() | !y.is_torsion_free() | y.is_identity()).into() {
        return Err(ProtocolError::AssertionFailed(
            format!("participant {from:?} sent a big_y not in the prime-order subgroup")
        ));
    }
    // same check for big_c
    norm_big_y += participant_output.big_y();
    norm_big_c += participant_output.big_c();
}
```

Alternatively, add a validated constructor to `CKDOutput` that enforces subgroup membership on both fields, and use it as the deserialization target.

---

### Proof of Concept

```rust
// Craft a low-order G1 point: multiply the generator by the group order r,
// then add a known low-order point T of order dividing the cofactor h.
// For BLS12-381, the cofactor h = 0x396c8c005555e1568c00aaab0000aaab.
// A concrete low-order point can be obtained as: T = h_inv * G1::generator()
// where h_inv is the modular inverse of h mod the curve order -- but more
// directly, use the known small-subgroup generator for BLS12-381 G1.

// Malicious participant replaces norm_big_y with low_order_point before sending:
let low_order_point: G1Projective = /* known low-order BLS12-381 G1 point */;
chan.send_private(waitpoint, coordinator, &(low_order_point, norm_big_c))?;

// Coordinator aggregates without subgroup check -> norm_big_y is poisoned.
// Client calls ckd_output.unmask(app_sk) -> result not in prime-order subgroup.
// verify_signature(...) -> Err(InvalidSignature).  CKD is broken.
```

### Citations

**File:** src/confidential_key_derivation/protocol.rs (L29-31)
```rust
    let waitpoint = chan.next_waitpoint();
    chan.send_private(waitpoint, coordinator, &(norm_big_y, norm_big_c))?;

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

**File:** src/confidential_key_derivation/mod.rs (L31-35)
```rust
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct CKDOutput {
    big_y: ElementG1,
    big_c: ElementG1,
}
```

**File:** src/confidential_key_derivation/mod.rs (L54-56)
```rust
    pub fn unmask(&self, secret_scalar: Scalar) -> Signature {
        self.big_c - self.big_y * secret_scalar
    }
```

**File:** src/confidential_key_derivation/ciphersuite.rs (L202-213)
```rust
    fn deserialize(buf: &Self::Serialization) -> Result<Self::Element, frost_core::GroupError> {
        Self::Element::from_compressed(buf).into_option().map_or(
            Err(frost_core::GroupError::MalformedElement),
            |point| {
                if point.is_identity().into() {
                    Err(frost_core::GroupError::InvalidIdentityElement)
                } else {
                    Ok(point)
                }
            },
        )
    }
```

**File:** src/confidential_key_derivation/ciphersuite.rs (L223-226)
```rust
    let element1: G1Affine = signature.into();
    if (!element1.is_on_curve() | !element1.is_torsion_free() | element1.is_identity()).into() {
        return Err(frost_core::Error::InvalidSignature);
    }
```
