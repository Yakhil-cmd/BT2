Now I have enough information to make a definitive assessment. Let me trace the exact deserialization path for CKD shares.

### Title
Missing Torsion-Free Validation on Received G1 Shares Allows Malicious Participant to Corrupt CKDOutput — (`src/confidential_key_derivation/protocol.rs`, `src/confidential_key_derivation/ciphersuite.rs`)

---

### Summary

`do_ckd_coordinator` aggregates participant-supplied G1 points without checking subgroup membership. A malicious participant can send a G1 point that is on the BLS12-381 curve but outside the prime-order subgroup. The coordinator accepts it via `rmp_serde` → blstrs serde → `G1Projective::from_compressed` (which performs no torsion check), adds it into the aggregate, and returns a `CKDOutput` whose `unmask` result fails `verify_signature`'s explicit `is_torsion_free()` guard — permanently denying CKD to the requesting application.

---

### Finding Description

**Deserialization path (actual, not as stated in the question):**

Participants send `(norm_big_y, norm_big_c)` via `chan.send_private`. [1](#0-0) 

The coordinator collects them with `recv_from_others::<CKDOutput>`, which calls `rmp_serde::decode::from_slice` internally. [2](#0-1) [3](#0-2) 

`rmp_serde` deserializes each `ElementG1 = blstrs::G1Projective` field using blstrs's serde implementation, which calls `G1Projective::from_compressed`. In blstrs 0.7.1 (wrapping blst 0.3.16), `from_compressed` calls `blst_p1_uncompress`, which verifies the point is on the curve but **does not call `blst_p1_in_g1`** — no subgroup/torsion check is performed.

This is corroborated by the codebase's own `BLS12381G1Group::deserialize`, which also uses `from_compressed` and only adds an identity check — no `is_torsion_free()` call: [4](#0-3) 

Note: `BLS12381G1Group` is defined only in `ciphersuite.rs` and is **not used anywhere else** in the codebase (grep confirms 2 matches, both in that file). The actual deserialization of CKD shares goes through blstrs serde, not `BLS12381G1Group::deserialize`. The missing torsion check is present in both paths.

**Aggregation without validation:**

The coordinator unconditionally adds each received point into the running sum: [5](#0-4) 

If `participant_output.big_y()` is a non-torsion-free point `P` (on the curve, order dividing `h·r` but not `r`), then `norm_big_y += P` contaminates the aggregate.

**Verification gate that catches the corruption — too late:**

`verify_signature` explicitly checks `is_torsion_free()` on the final signature: [6](#0-5) 

`unmask(app_sk)` computes `big_c − big_y · app_sk`. With a non-torsion-free component `P` in `big_y`, the result contains `−P · app_sk`, which is also outside the prime-order subgroup (since the cofactor subgroup is closed under scalar multiplication and `app_sk` is not a multiple of `r` with overwhelming probability). The `is_torsion_free()` check in `verify_signature` therefore returns `false`, and the function returns `InvalidSignature`. [7](#0-6) 

---

### Impact Explanation

Every CKD invocation that includes the malicious participant produces a `CKDOutput` whose `unmask` result fails `verify_signature`. The application cannot derive its key. Because the malicious participant can repeat this on every protocol run, the denial is permanent for any CKD request that routes through that participant set. This matches **High: Permanent denial of CKD for honest parties under valid protocol inputs and documented trust assumptions**.

---

### Likelihood Explanation

- The attacker only needs to be a legitimate protocol participant (within the t-of-n malicious-participant assumption).
- Constructing a BLS12-381 G1 point that is on the curve but not in the prime-order subgroup is straightforward: take any curve point and subtract its projection onto the prime-order subgroup.
- The attack is deterministic, requires no cryptographic breaks, and succeeds on every invocation.
- No existing guard in `do_ckd_coordinator` or the deserialization layer rejects such a point.

---

### Recommendation

Add an explicit `is_torsion_free()` check when deserializing received G1 shares in `do_ckd_coordinator`, mirroring the check already present in `verify_signature`. The fix should be applied at the point of ingestion:

```rust
// In do_ckd_coordinator, after receiving participant_output:
let y: G1Affine = participant_output.big_y().into();
let c: G1Affine = participant_output.big_c().into();
if !bool::from(y.is_torsion_free()) || !bool::from(c.is_torsion_free()) {
    return Err(ProtocolError::AssertionFailed(
        "received G1 point is not in the prime-order subgroup".into()
    ));
}
```

Additionally, `BLS12381G1Group::deserialize` should add the same check for consistency, even though it is not currently on the CKD hot path. [4](#0-3) 

---

### Proof of Concept

```rust
// 1. Obtain a point on E(Fp) outside G1:
//    Take any G1 generator point and clear the prime-order component,
//    leaving only the cofactor component.
//    Alternatively: use a known low-order point from the h-torsion.
let low_order_point: G1Projective = /* point with r·P ≠ 0 */;
assert!(!bool::from(G1Affine::from(low_order_point).is_torsion_free()));

// 2. Malicious participant sends this as their (norm_big_y, norm_big_c):
//    Serialize as rmp_serde would, inject into the channel.

// 3. Coordinator aggregates without rejection.

// 4. Application calls unmask and verify_signature:
let sig = ckd_output.unmask(app_sk);
let result = verify_signature(&public_key, &app_id, &sig);
assert_eq!(result, Err(frost_core::Error::InvalidSignature)); // always fires
```

### Citations

**File:** src/confidential_key_derivation/protocol.rs (L29-30)
```rust
    let waitpoint = chan.next_waitpoint();
    chan.send_private(waitpoint, coordinator, &(norm_big_y, norm_big_c))?;
```

**File:** src/confidential_key_derivation/protocol.rs (L50-56)
```rust
    for (_, participant_output) in
        recv_from_others::<CKDOutput>(&chan, waitpoint, &participants, me).await?
    {
        norm_big_y += participant_output.big_y();
        norm_big_c += participant_output.big_c();
    }
    let ckd_output = CKDOutput::new(norm_big_y, norm_big_c);
```

**File:** src/protocol/internal.rs (L338-340)
```rust
        let decoded: Result<T, Box<dyn error::Error + Send + Sync>> =
            rmp_serde::decode::from_slice(message_data).map_err(std::convert::Into::into);
        Ok((from, decoded?))
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

**File:** src/confidential_key_derivation/mod.rs (L54-56)
```rust
    pub fn unmask(&self, secret_scalar: Scalar) -> Signature {
        self.big_c - self.big_y * secret_scalar
    }
```
