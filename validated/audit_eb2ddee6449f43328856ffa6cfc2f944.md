The code is fully readable. Here is the complete analysis.

---

**Confirmed code facts:**

`parse_g1_bytes` / `parse_g2_bytes` in `crypto/src/bls12_381/eip2537.rs`: [1](#0-0) [2](#0-1) 

Both use `new_unchecked` and only call `is_on_curve()` — no subgroup check.

`parse_g1` / `parse_g2` (used by G1ADD and G2ADD) call these directly: [3](#0-2) 

`parse_g1_with_subgroup_check` / `parse_g2_with_subgroup_check` exist and do call `is_in_correct_subgroup_assuming_on_curve()`: [4](#0-3) 

G1ADD and G2ADD use the unchecked variants: [5](#0-4) 

The pairing precompile uses the checked variants: [6](#0-5) 

---

### Title
Missing Subgroup Check in G1ADD/G2ADD Causes EIP-2537 Non-Compliance and Execution Divergence — (`basic_bootloader/src/bootloader/block_flow/ethereum/hooks/eip_2537/addition.rs`, `crypto/src/bls12_381/eip2537.rs`)

### Summary

G1ADD and G2ADD accept BLS12-381 points that lie on the curve but outside the prime-order subgroup. EIP-2537 explicitly requires these precompiles to reject such points with an error. The result is that a transaction calling G1ADD/G2ADD with a small-subgroup point **succeeds** on ZKsync OS but **reverts** on Ethereum mainnet, producing a provably different execution.

### Finding Description

`parse_g1_bytes` constructs a `G1Affine` with `new_unchecked` and only validates `is_on_curve()`:

```rust
// crypto/src/bls12_381/eip2537.rs:44-48
let point = G1Affine::new_unchecked(x, y);
if !point.is_on_curve() {
    return None;
}
Some((point, true))
```

`parse_g1_with_subgroup_check` (lines 102–113 of `mod.rs`) adds the missing guard:

```rust
if point.is_zero() || point.is_in_correct_subgroup_assuming_on_curve() {
    Ok(point)
} else {
    Err(interface_error!(Bls12PrecompileInterfaceError::PointNotInSubgroup))
}
```

G1ADD and G2ADD call `parse_g1` / `parse_g2` (the unchecked wrappers). The checked wrappers are only wired into MSM and pairing. The `PointNotInSubgroup` error variant exists and is used — just not by the addition precompiles.

### Impact Explanation

EIP-2537 mandates that G1ADD and G2ADD return an error for points not in the correct subgroup. On Ethereum mainnet these calls revert; on ZKsync OS they succeed and return a result. Any smart contract that relies on G1ADD reverting for out-of-subgroup inputs will behave differently on ZKsync OS, and the ZKsync OS execution trace (which shows success) is provably inconsistent with the Ethereum-equivalent execution (which shows revert). This is a concrete execution-divergence / invalid-provable-execution bug reachable by any unprivileged caller.

**Correction to the question's specific claim:** The "breaks pairing soundness in a subsequent call" path is **not** achievable. The pairing precompile independently calls `parse_g1_with_subgroup_check` / `parse_g2_with_subgroup_check` on its own inputs. The output of G1ADD on small-subgroup inputs is itself a small-subgroup point, which the pairing precompile would reject. Pairing soundness is not broken by this bug.

The real impact is narrower but still concrete: **execution divergence** — G1ADD/G2ADD succeed where Ethereum mainnet would revert.

### Likelihood Explanation

Any unprivileged user can construct a BLS12-381 G1 point of small order (multiply the generator by the cofactor `h = 0x396c8c005555e1568c00aaab0000aaab`), submit it to the G1ADD precompile, and observe the divergence. No special access is required.

### Recommendation

Replace `parse_g1` / `parse_g2` with `parse_g1_with_subgroup_check` / `parse_g2_with_subgroup_check` in `addition.rs`:

```rust
// addition.rs lines 34-39 — change to:
let p0 = parse_g1_with_subgroup_check(input[0..G1_SERIALIZATION_LEN].try_into().unwrap())?;
let p1 = parse_g1_with_subgroup_check(
    input[G1_SERIALIZATION_LEN..(2 * G1_SERIALIZATION_LEN)].try_into().unwrap(),
)?;
```

Apply the same fix to G2ADD.

### Proof of Concept

1. Compute `P_small = h * G1_generator` where `h` is the BLS12-381 G1 cofactor. This point is on the curve (`is_on_curve() == true`) but `is_in_correct_subgroup_assuming_on_curve() == false`.
2. Encode `P_small` twice (128 bytes each) as the G1ADD input (256 bytes total).
3. Call the G1ADD precompile (`0x0b`) on ZKsync OS. It returns success and a result.
4. On Ethereum mainnet (or any EIP-2537-compliant implementation), the same call reverts with "point not in subgroup."
5. The ZKsync OS execution trace records a successful precompile call; the Ethereum-equivalent trace records a revert — execution divergence is demonstrated.

### Citations

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

**File:** crypto/src/bls12_381/eip2537.rs (L54-67)
```rust
pub fn parse_g2_bytes(input: &[u8; G2_LEN]) -> Option<(G2Affine, bool)> {
    if input.iter().all(|el| *el == 0) {
        return Some((G2Affine::identity(), false));
    }
    let x = parse_fq2_bytes(input[0..128].try_into().ok()?)?;
    let y = parse_fq2_bytes(input[128..256].try_into().ok()?)?;
    let point = G2Affine::new_unchecked(x, y);

    if !point.is_on_curve() {
        return None;
    }

    Some((point, true))
}
```

**File:** basic_bootloader/src/bootloader/block_flow/ethereum/hooks/eip_2537/mod.rs (L90-100)
```rust
fn parse_g1(input: &[u8; G1_SERIALIZATION_LEN]) -> Result<G1Affine, Bls12PrecompileSubsystemError> {
    crypto::bls12_381::eip2537::parse_g1_bytes(input)
        .map(|(point, _)| point)
        .ok_or_else(|| interface_error!(Bls12PrecompileInterfaceError::InvalidG1Point))
}

fn parse_g2(input: &[u8; G2_SERIALIZATION_LEN]) -> Result<G2Affine, Bls12PrecompileSubsystemError> {
    crypto::bls12_381::eip2537::parse_g2_bytes(input)
        .map(|(point, _)| point)
        .ok_or_else(|| interface_error!(Bls12PrecompileInterfaceError::InvalidG1Point))
}
```

**File:** basic_bootloader/src/bootloader/block_flow/ethereum/hooks/eip_2537/mod.rs (L102-126)
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

fn parse_g2_with_subgroup_check(
    input: &[u8; G2_SERIALIZATION_LEN],
) -> Result<G2Affine, Bls12PrecompileSubsystemError> {
    let point = parse_g2(input)?;
    if point.is_zero() || point.is_in_correct_subgroup_assuming_on_curve() {
        Ok(point)
    } else {
        Err(interface_error!(
            Bls12PrecompileInterfaceError::PointNotInSubgroup
        ))
    }
}
```

**File:** basic_bootloader/src/bootloader/block_flow/ethereum/hooks/eip_2537/addition.rs (L34-44)
```rust
        let p0 = parse_g1(input[0..G1_SERIALIZATION_LEN].try_into().unwrap())?;
        let p1 = parse_g1(
            input[G1_SERIALIZATION_LEN..(2 * G1_SERIALIZATION_LEN)]
                .try_into()
                .unwrap(),
        )?;

        let result = p0 + p1;
        let result = result.into_affine();

        write_g1(result, output);
```

**File:** basic_bootloader/src/bootloader/block_flow/ethereum/hooks/eip_2537/pairing.rs (L55-66)
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
            g1_points.push(g1);
            g2_points.push(g2);
        }
```
