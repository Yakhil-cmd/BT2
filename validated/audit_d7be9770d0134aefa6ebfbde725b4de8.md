The math and code path are fully traceable. Let me confirm the `deserialize_compressed` validation mode used.

The full exploit path is confirmed. Here is the assessment:

---

### Title
KZG Point Evaluation Precompile Accepts Identity-Point Proof, Diverging from EVM Reference — (`basic_system/src/system_functions/point_evaluation.rs`)

### Summary
`point_evaluation_as_system_function_inner` does not reject the BLS12-381 identity (point-at-infinity) as commitment or proof. When both are the identity and `z = y = 0`, `verify_kzg_proof` trivially returns `true` because `multi_pairing([O, O], [...]) = 1_GT`. The EVM reference implementation (c-kzg-4844, used by revm) explicitly rejects the identity point via `validate_kzg_g1`. ZKsync OS therefore accepts a proof that Ethereum mainnet rejects, constituting a concrete EVM deviation.

### Finding Description

**Step 1 — Identity point passes `parse_g1_compressed`.**

`parse_g1_compressed` calls `G1Affine::deserialize_compressed`, which internally calls `read_g1_compressed`. When the infinity flag is set (`0xc0 00…00`), `read_g1_compressed` immediately returns `G1Affine::zero()` with no rejection: [1](#0-0) 

The existing test suite even asserts this is intentional: [2](#0-1) 

**Step 2 — Scalars `z = 0` and `y = 0` pass `parse_scalar`.**

`parse_scalar` only rejects values `>= Fr::MODULUS`. Zero is strictly less than the modulus and passes: [3](#0-2) 

**Step 3 — Versioned hash check is trivially satisfiable.**

The attacker computes `versioned_hash_for_kzg(identity_bytes)` offline (SHA-256 of `0xc0 00…00` with first byte replaced by `0x01`) and includes it as the first 32 bytes of input: [4](#0-3) 

**Step 4 — `verify_kzg_proof(O, O, 0, 0)` returns `true`.**

With `y = 0` and `commitment = O`:
- `y_minus_p = G1.generator() * 0 − O = O − O = O`

With `z = 0` and `proof = O`:
- `g2_el = G2_BY_TAU_POINT − G2.generator() * 0 = G2_BY_TAU_POINT`

The multi-pairing call becomes `multi_pairing([O, O], [G2_gen, G2_BY_TAU_POINT])`. Since `e(O, Q) = 1_GT` for any `Q`, the product is `1_GT`, and the equality check passes: [5](#0-4) 

**Step 5 — No guard exists between parsing and `verify_kzg_proof`.**

There is no `is_zero()` / identity check on `commitment_point` or `proof` before the pairing call: [6](#0-5) 

**Contrast with EVM reference.** c-kzg-4844 (the library used by revm and Ethereum clients) calls `validate_kzg_g1` before any pairing, which returns `C_KZG_BADARGS` if `is_infinity_g1(p)`. The fuzzer harness that compares ZKsync OS output against revm would catch this divergence: [7](#0-6) 

### Impact Explanation
Any smart contract on ZKsync OS that calls the KZG point evaluation precompile (address `0x0a`) to verify blob data integrity can be bypassed by an unprivileged attacker supplying `(versioned_hash_for_kzg(identity), 0, 0, identity, identity)`. The precompile returns the standard success response `4096 || BLS_MODULUS` instead of reverting. On Ethereum mainnet the identical input reverts. Contracts that gate logic on a successful KZG proof (e.g., blob-data availability proofs, EIP-4844-based bridges) are vulnerable to proof forgery on ZKsync OS.

### Likelihood Explanation
The exploit requires no privileged access, no leaked keys, and no external oracle. The 192-byte input is fully attacker-controlled and the versioned hash is deterministically computable. Any caller of the precompile can trigger this path.

### Recommendation
Add an explicit identity-point rejection in `parse_g1_compressed` (or directly in `point_evaluation_as_system_function_inner`) before passing points to `verify_kzg_proof`:

```rust
let Ok(commitment_point) = parse_g1_compressed(commitment) else { … };
if commitment_point.is_zero() {
    return Err(interface_error!(PointEvaluationInterfaceError::InvalidPoint));
}
// … same for proof …
let Ok(proof) = parse_g1_compressed(proof) else { … };
if proof.is_zero() {
    return Err(interface_error!(PointEvaluationInterfaceError::InvalidPoint));
}
```

This matches the behaviour of c-kzg-4844's `validate_kzg_g1`.

### Proof of Concept

```
commitment_bytes = 0xc0 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
                     00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
                     00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
                     (48 bytes: compressed infinity point)

versioned_hash  = 0x01 || SHA256(commitment_bytes)[1:]
                  (32 bytes, trivially computable)

z               = 0x00 * 32   (32 bytes)
y               = 0x00 * 32   (32 bytes)
proof_bytes     = commitment_bytes  (same identity point, 48 bytes)

input = versioned_hash || z || y || commitment_bytes || proof_bytes
      = 192 bytes total
```

Calling `PointEvaluationImpl::execute(&input, …)` on ZKsync OS returns `Ok(())` with output `4096 || BLS_MODULUS`. The identical call via revm returns `Err(…)` (invalid point). The divergence is directly observable by the existing fuzzer at `tests/fuzzer/fuzz/fuzz_targets/precompiles/precompiles_kzg_point_eval.rs`. [8](#0-7) [9](#0-8)

### Citations

**File:** crypto/src/bls12_381/curves/util.rs (L144-178)
```rust
pub(crate) fn read_g1_compressed<R: ark_serialize::Read>(
    mut reader: R,
) -> Result<Affine<G1Config>, ark_serialize::SerializationError> {
    let mut bytes = [0u8; G1_SERIALIZED_SIZE];
    reader
        .read_exact(&mut bytes)
        .ok()
        .ok_or(SerializationError::InvalidData)?;

    // Obtain the three flags from the start of the byte sequence
    let flags = EncodingFlags::get_flags(&bytes[..])?;

    // We expect to be deserializing a compressed point
    if !flags.is_compressed {
        return Err(SerializationError::UnexpectedFlags);
    }

    // Attempt to obtain the x-coordinate
    let x_bytes = read_bytes_with_offset(&bytes, 0, true);

    if flags.is_infinity {
        // Check that the `x` co-ordinate was `0`
        if x_bytes != [0u8; 48] {
            return Err(SerializationError::InvalidData);
        }

        return Ok(G1Affine::zero());
    }

    let x = deserialize_fq(x_bytes).ok_or(SerializationError::InvalidData)?;
    let p = G1Affine::get_point_from_x_unchecked(x, flags.is_lexographically_largest)
        .ok_or(SerializationError::InvalidData)?;

    Ok(p)
}
```

**File:** basic_system/src/system_functions/point_evaluation.rs (L55-63)
```rust
fn parse_scalar(input: &[u8; 32]) -> Result<<crypto::bls12_381::Fr as PrimeField>::BigInt, ()> {
    // Arkworks has strange format for integer serialization, so we do manually
    let result = crypto::parse_u256_be(input);
    if result >= crypto::bls12_381::Fr::MODULUS {
        Err(())
    } else {
        Ok(result)
    }
}
```

**File:** basic_system/src/system_functions/point_evaluation.rs (L65-69)
```rust
pub fn parse_g1_compressed(input: &[u8]) -> Result<crypto::bls12_381::G1Affine, ()> {
    // format coincides with one defined in ZCash/Arkworks
    use crypto::ark_serialize::CanonicalDeserialize;
    crypto::bls12_381::G1Affine::deserialize_compressed(input).map_err(|_| ())
}
```

**File:** basic_system/src/system_functions/point_evaluation.rs (L90-98)
```rust
    let versioned_hash = &input[..32];
    let commitment = &input[96..144];

    // so far it's just one version
    if versioned_hash_for_kzg(commitment) != versioned_hash {
        return Err(interface_error!(
            PointEvaluationInterfaceError::InvalidVersionedHash
        ));
    }
```

**File:** basic_system/src/system_functions/point_evaluation.rs (L100-133)
```rust
    // Parse the commitment and proof
    let Ok(commitment_point) = parse_g1_compressed(commitment) else {
        return Err(interface_error!(
            PointEvaluationInterfaceError::InvalidPoint
        ));
    };
    let proof = &input[144..192];
    let Ok(proof) = parse_g1_compressed(proof) else {
        return Err(interface_error!(
            PointEvaluationInterfaceError::InvalidPoint
        ));
    };

    let Ok(z) = parse_scalar(input[32..64].try_into().unwrap()) else {
        return Err(interface_error!(
            PointEvaluationInterfaceError::InvalidScalar
        ));
    };

    let Ok(y) = parse_scalar(input[64..96].try_into().unwrap()) else {
        return Err(interface_error!(
            PointEvaluationInterfaceError::InvalidScalar
        ));
    };

    if crypto::bls12_381::verify_kzg_proof(commitment_point, proof, z, y) {
        dst.try_extend(POINT_EVAL_PRECOMPILE_SUCCESS_RESPONSE)
            .map_err(|_| out_of_return_memory!())?;
        Ok(())
    } else {
        Err(interface_error!(
            PointEvaluationInterfaceError::PairingMismatch
        ))
    }
```

**File:** basic_system/src/system_functions/point_evaluation.rs (L374-384)
```rust
        // Test valid identity element (point at infinity)
        let identity = [
            0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        assert!(
            parse_g1_compressed(&identity).is_ok(),
            "Identity point should be valid"
        );
```

**File:** crypto/src/bls12_381/mod.rs (L24-39)
```rust
    let mut y_minus_p = G1Affine::generator().mul_bigint(&y);
    y_minus_p -= &commitment;

    let mut g2_el: G2Projective = G2_BY_TAU_POINT.into();
    let z_in_g2 = G2Affine::generator().mul_bigint(&z);
    g2_el -= z_in_g2;

    use crate::ark_ec::CurveGroup;
    let y_minus_p_prepared: G1Affine = y_minus_p.into_affine();
    let g2_el: <curves::Bls12_381 as Pairing>::G2Prepared = g2_el.into_affine().into();

    let gt_el = curves::Bls12_381::multi_pairing(
        [y_minus_p_prepared, proof],
        [PREPARED_G2_GENERATOR.clone(), g2_el],
    );
    gt_el.0 == <curves::Bls12_381 as Pairing>::TargetField::ONE
```

**File:** tests/fuzzer/fuzz/fuzz_targets/precompiles/precompiles_kzg_point_eval.rs (L79-84)
```rust
    let revm_res = kzg_point_evaluation::run(&bytes, 1 << 27);

    match revm_res {
        Ok(revm) => assert_eq!(zksync_os_bytes, revm.bytes.to_vec()),
        Err(_) => assert!(common::is_zero(zksync_os_bytes)),
    }
```
