### Title
BLS12-381 G1ADD and G2ADD Precompiles Silently Accept Points Outside the Correct Subgroup - (`File: basic_bootloader/src/bootloader/block_flow/ethereum/hooks/eip_2537/addition.rs`)

---

### Summary

The `Bls12381G1AdditionPrecompile` and `Bls12381G2AdditionPrecompile` implementations of EIP-2537 in ZKsync OS omit the mandatory subgroup membership check on their input points. The MSM and Pairing precompiles correctly use `parse_g1_with_subgroup_check` / `parse_g2_with_subgroup_check`, but the addition precompiles use the weaker `parse_g1` / `parse_g2` helpers that only verify the point is on the curve. An unprivileged caller can supply a point that lies on the BLS12-381 curve but outside the prime-order subgroup G1 (or G2), and the precompile will silently compute and return a result instead of reverting, diverging from the EIP-2537 specification and from every other compliant implementation.

---

### Finding Description

EIP-2537 explicitly lists "Point is not in the correct subgroup" as a mandatory error case for both `BLS12_G1ADD` and `BLS12_G2ADD`. The ZKsync OS codebase defines two helper functions in `mod.rs`:

- `parse_g1` — calls `parse_g1_bytes`, which only checks `is_on_curve()`.
- `parse_g1_with_subgroup_check` — additionally calls `is_in_correct_subgroup_assuming_on_curve()` and returns `PointNotInSubgroup` if the check fails.

The G1MSM, G2MSM, and Pairing precompiles all use the subgroup-checking variant:

```
// msm.rs line 219
let point = parse_g1_with_subgroup_check(...)?;

// pairing.rs line 56
let g1 = parse_g1_with_subgroup_check(...)?;
let g2 = parse_g2_with_subgroup_check(...)?;
```

But the addition precompiles use only the weaker helper:

```
// addition.rs lines 34-39
let p0 = parse_g1(input[0..G1_SERIALIZATION_LEN].try_into().unwrap())?;
let p1 = parse_g1(input[G1_SERIALIZATION_LEN..].try_into().unwrap())?;
let result = p0 + p1;
```

`parse_g1_bytes` in `crypto/src/bls12_381/eip2537.rs` only validates that the point is on the curve:

```rust
if !point.is_on_curve() {
    return None;
}
```

It never calls `is_in_correct_subgroup_assuming_on_curve()`. A point on the BLS12-381 curve but outside the prime-order subgroup passes this check and is accepted.

---

### Impact Explanation

**Vulnerability class**: EVM semantic mismatch / precompile input-domain validation bug.

1. **State-transition divergence**: Any EIP-2537-compliant chain (Ethereum mainnet after Pectra) rejects G1ADD/G2ADD calls with out-of-subgroup points. ZKsync OS accepts them and returns a result. A transaction that should revert on Ethereum succeeds on ZKsync OS, producing a different state root — a direct forward/proving divergence.

2. **Incorrect cryptographic output**: The sum of two points outside the correct subgroup is itself outside the subgroup. Smart contracts that use G1ADD as a building block for BLS signature aggregation or ZK proof verification will receive a mathematically invalid result with no indication of failure, silently corrupting the cryptographic computation.

3. **Inconsistency within the same codebase**: The MSM and Pairing precompiles correctly reject the same class of invalid points. An attacker can exploit the inconsistency: a point rejected by G1MSM is accepted by G1ADD, allowing crafted inputs to bypass the subgroup check entirely by routing through the addition precompile.

---

### Likelihood Explanation

**High.** The entry path requires only an unprivileged `CALL` to precompile address `0x0b` (G1ADD) or `0x0d` (G2ADD) with a 256-byte input containing a point that is on the BLS12-381 curve but not in the prime-order subgroup. Such points are easy to construct (any point on the curve with cofactor ≠ 1 component). No privileged access, oracle manipulation, or key material is required.

---

### Recommendation

Replace `parse_g1` / `parse_g2` with `parse_g1_with_subgroup_check` / `parse_g2_with_subgroup_check` in both addition precompiles, exactly as is already done in the MSM and Pairing precompiles:

```rust
// addition.rs — Bls12381G1AdditionPrecompile
let p0 = parse_g1_with_subgroup_check(input[0..G1_SERIALIZATION_LEN].try_into().unwrap())?;
let p1 = parse_g1_with_subgroup_check(input[G1_SERIALIZATION_LEN..].try_into().unwrap())?;

// addition.rs — Bls12381G2AdditionPrecompile
let p0 = parse_g2_with_subgroup_check(input[0..G2_SERIALIZATION_LEN].try_into().unwrap())?;
let p1 = parse_g2_with_subgroup_check(input[G2_SERIALIZATION_LEN..].try_into().unwrap())?;
```

---

### Proof of Concept

**Root cause — addition precompile uses `parse_g1` (no subgroup check):** [1](#0-0) 

**Root cause — `parse_g1` only checks `is_on_curve()`, not subgroup membership:** [2](#0-1) 

**Contrast — MSM precompile correctly uses `parse_g1_with_subgroup_check`:** [3](#0-2) 

**Contrast — Pairing precompile correctly uses subgroup-checking helpers:** [4](#0-3) 

**The subgroup-checking helper that addition precompiles should use:** [5](#0-4) 

**G2 addition precompile — same missing check:** [6](#0-5)

### Citations

**File:** basic_bootloader/src/bootloader/block_flow/ethereum/hooks/eip_2537/addition.rs (L34-39)
```rust
        let p0 = parse_g1(input[0..G1_SERIALIZATION_LEN].try_into().unwrap())?;
        let p1 = parse_g1(
            input[G1_SERIALIZATION_LEN..(2 * G1_SERIALIZATION_LEN)]
                .try_into()
                .unwrap(),
        )?;
```

**File:** basic_bootloader/src/bootloader/block_flow/ethereum/hooks/eip_2537/addition.rs (L75-83)
```rust
        let p0 = parse_g2(input[0..G2_SERIALIZATION_LEN].try_into().unwrap())?;
        let p1 = parse_g2(
            input[G2_SERIALIZATION_LEN..(2 * G2_SERIALIZATION_LEN)]
                .try_into()
                .unwrap(),
        )?;

        let result = p0 + p1;
        let result = result.into_affine();
```

**File:** crypto/src/bls12_381/eip2537.rs (L38-51)
```rust
pub fn parse_g1_bytes(input: &[u8; G1_LEN]) -> Option<(G1Affine, bool)> {
    if input.iter().all(|el| *el == 0) {
        return Some((G1Affine::identity(), false));
    }
    let x = parse_fq_bytes(input[0..64].try_into().ok()?)?;
    let y = parse_fq_bytes(input[64..128].try_into().ok()?)?;
    let point = G1Affine::new_unchecked(x, y);

    if !point.is_on_curve() {
        return None;
    }

    Some((point, true))
}
```

**File:** basic_bootloader/src/bootloader/block_flow/ethereum/hooks/eip_2537/msm.rs (L218-221)
```rust
        for pair_encoding in input.as_chunks::<G1_MSM_PAIR_LEN>().0.iter() {
            let point = parse_g1_with_subgroup_check(
                pair_encoding[0..G1_SERIALIZATION_LEN].try_into().unwrap(),
            )?;
```

**File:** basic_bootloader/src/bootloader/block_flow/ethereum/hooks/eip_2537/pairing.rs (L55-63)
```rust
        for pair_encoding in input.as_chunks::<BLS12_381_PAIR_LEN>().0.iter() {
            let g1 = parse_g1_with_subgroup_check(
                pair_encoding[0..G1_SERIALIZATION_LEN].try_into().unwrap(),
            )?;
            let g2 = parse_g2_with_subgroup_check(
                pair_encoding[G1_SERIALIZATION_LEN..(G1_SERIALIZATION_LEN + G2_SERIALIZATION_LEN)]
                    .try_into()
                    .unwrap(),
            )?;
```

**File:** basic_bootloader/src/bootloader/block_flow/ethereum/hooks/eip_2537/mod.rs (L102-113)
```rust
fn parse_g1_with_subgroup_check(
    input: &[u8; G1_SERIALIZATION_LEN],
) -> Result<G1Affine, Bls12PrecompileSubsystemError> {
    let point = parse_g1(input)?;
    if point.is_zero() || point.is_in_correct_subgroup_assuming_on_curve() {
        Ok(point)
    } else {
        Err(interface_error!(
            Bls12PrecompileInterfaceError::PointNotInSubgroup
        ))
    }
}
```
