### Title
Missing G2 Subgroup Check in `alt_bn128_pairing_check` Host Function - (File: `runtime/near-vm-runner/src/logic/alt_bn128.rs`)

### Summary
The NEAR runtime exposes an `alt_bn128_pairing_check` host function that any smart contract can call to perform BN254 (alt_bn128) elliptic-curve pairing checks — typically used to verify zk-SNARK proofs on-chain. The G2 point decoding routine `decode_g2` only validates that the supplied coordinates satisfy the twisted curve equation, but never verifies that the point belongs to the correct prime-order (r-order) subgroup. This is the exact bug class described in the external report for `pairing_certificate.rs`, but here it is present in code that is *not* just witness generation — it is live, gas-metered production logic reachable from any unprivileged contract call.

### Finding Description
`decode_g2` in [1](#0-0)  constructs a `bn::G2` point using `bn::AffineG2::new(x, y)`, which only checks the point lies on the twisted curve `E'(Fq2)`, with no subsequent check that `[r]P = O` for the subgroup order `r`. This decoded (possibly off-subgroup) G2 point is then fed directly into `bn::pairing_batch` inside `pairing_check` at [2](#0-1) .

This function is wired to the public host function `alt_bn128_pairing_check`, invocable by any contract via wasm at [3](#0-2)  (and equivalently in the wasmtime runner at [4](#0-3) ). The doc comment even claims G2 must be "Fr-ordered subgroup point," but the implementation never enforces this claim [5](#0-4) .

By contrast, the BLS12-381 pairing check implemented alongside it explicitly performs subgroup checks on both G1 and G2 points via `blst_p1_affine_in_g1` and `blst_p2_affine_in_g2` before running the pairing [6](#0-5) . This shows the omission in the alt_bn128 path is an inconsistency/gap rather than an intentional design choice.

### Impact Explanation
`alt_bn128_pairing_check` is the standard precompile used by contracts implementing Groth16/BN254-based zk-SNARK verifiers (a very common pattern for privacy pools, zk-rollup bridges, and proof-of-computation contracts) since BN254 is the most widely supported pairing-friendly curve in the SNARK toolchain ecosystem. If an attacker can construct a G2 point that lies on the twist curve but outside the correct r-order subgroup, and that point satisfies the pairing equation the verifier checks, they could potentially craft proofs that pass verification without possessing a valid witness. In a deployed contract relying on this host function for proof soundness (e.g., a bridge or mixer verifying withdrawal proofs), this could lead to unauthorized state changes, forged proofs, or fund theft from that contract — all triggered purely through an ordinary contract call/transaction, no validator or node privilege required.

### Likelihood Explanation
Reaching the vulnerable code path requires only a standard `FunctionCall` transaction/receipt invoking `alt_bn128_pairing_check` with attacker-supplied bytes — this is fully reachable by any account with no privileged access. Actually exploiting it to forge a valid pairing result requires constructing a specific off-subgroup point that also satisfies the target pairing relation, which is a nontrivial cryptographic construction; the practical exploitability depends on properties of the BN254 twist's cofactor structure. Regardless of exploit difficulty, the missing defense-in-depth check is a genuine deviation from the documented security contract ("G2 is Fr-ordered subgroup point") and from the parallel BLS12-381 implementation in the same codebase.

### Recommendation
Add an explicit subgroup check for decoded G2 points in `decode_g2` (and ideally G1 points in `decode_g1`, since BN254 G1 in principle also requires it, though its cofactor is 1), e.g., by multiplying the point by the subgroup order `r` and checking the result is the identity, or using an efficient endomorphism-based subgroup test analogous to the one already used for BLS12-381 (`blst_p2_affine_in_g2`). Align the alt_bn128 pairing check implementation with the security guarantees already implemented for BLS12-381 in `bls12381.rs`.

### Proof of Concept
A concrete PoC requires constructing a G2 point on the BN254 twist `E'(Fq2): Y^2 = X^3 + 3/(9+i)` that lies outside the r-order subgroup yet satisfies a chosen pairing relation used by a target verifier contract — this is a nontrivial cryptographic construction task, not merely a code-path demonstration. At the code level, the reachability can be trivially confirmed: any contract can call `alt_bn128_pairing_check(value_len, value_ptr)` with attacker-controlled `value` bytes decoded via `super::alt_bn128::pairing_check` → `decode_g2`, which performs no subgroup validation, as shown in [1](#0-0) .

### Citations

**File:** runtime/near-vm-runner/src/logic/alt_bn128.rs (L77-93)
```rust
pub(crate) fn pairing_check(
    elements: &[[u8; PAIRING_CHECK_ELEMENT_SIZE]],
) -> Result<bool, InvalidInput> {
    let elements: Vec<(bn::G1, bn::G2)> = elements
        .iter()
        .map(|chunk| {
            let (g1, g2) = stdx::split_array(chunk);
            let g1 = decode_g1(g1)?;
            let g2 = decode_g2(g2)?;
            Ok((g1, g2))
        })
        .collect::<Result<Vec<_>, InvalidInput>>()?;

    let res = bn::pairing_batch(&elements) == bn::Gt::one();

    Ok(res)
}
```

**File:** runtime/near-vm-runner/src/logic/alt_bn128.rs (L131-142)
```rust
fn decode_g2(raw: &[u8; 2 * POINT_SIZE]) -> Result<bn::G2, InvalidInput> {
    let (x, y) = stdx::split_array(raw);
    let x = decode_fq2(x)?;
    let y = decode_fq2(y)?;
    if x.is_zero() && y.is_zero() {
        Ok(bn::G2::zero())
    } else {
        bn::AffineG2::new(x, y)
            .map_err(|_err| InvalidInput::new("invalid g2", raw))
            .map(bn::G2::from)
    }
}
```

**File:** runtime/near-vm-runner/src/logic/logic.rs (L1097-1105)
```rust
    /// * `value` - sequence of (g1:G1, g2:G2), where
    ///   G2 is Fr-ordered subgroup point (x:Fq2, y:Fq2) on alt_bn128 twist,
    ///   alt_bn128 twist is Y^2 = X^3 + 3/(i+9) curve over Fq2
    ///   Fq2 is complex field element (re: Fq, im: Fq)
    ///   G1 is point (x:Fq, y:Fq) on alt_bn128,
    ///   alt_bn128 is Y^2 = X^3 + 3 curve over Fq
    ///
    ///   `value` is encoded a as packed, little-endian
    ///   `[((u256, u256), ((u256, u256), (u256, u256)))]` slice.
```

**File:** runtime/near-vm-runner/src/logic/logic.rs (L1119-1131)
```rust
    pub fn alt_bn128_pairing_check(&mut self, value_len: u64, value_ptr: u64) -> Result<u64> {
        self.result_state.gas_counter.pay_base(alt_bn128_pairing_check_base)?;
        let data = get_memory_or_register!(self, value_ptr, value_len)?;

        let elements = super::alt_bn128::split_elements(&data)?;
        self.result_state
            .gas_counter
            .pay_per(alt_bn128_pairing_check_element, elements.len() as u64)?;

        let res = super::alt_bn128::pairing_check(elements)?;

        Ok(res as u64)
    }
```

**File:** runtime/near-vm-runner/src/wasmtime_runner/logic.rs (L1030-1051)
```rust
pub fn alt_bn128_pairing_check(
    ctx: &mut Ctx,
    memory: &mut [u8],
    value_len: u64,
    value_ptr: u64,
) -> Result<u64> {
    ctx.result_state.gas_counter.pay_base(alt_bn128_pairing_check_base)?;
    let data = get_memory_or_register(
        &mut ctx.result_state.gas_counter,
        memory,
        &ctx.registers,
        value_ptr,
        value_len,
    )?;

    let elements = alt_bn128::split_elements(&data)?;
    ctx.result_state.gas_counter.pay_per(alt_bn128_pairing_check_element, elements.len() as u64)?;

    let res = alt_bn128::pairing_check(elements)?;

    Ok(res as u64)
}
```

**File:** runtime/near-vm-runner/src/logic/bls12381.rs (L354-372)
```rust
        let g1_check = unsafe { blst::blst_p1_affine_in_g1(&blst_g1_list[i]) };
        if g1_check == false {
            return Ok(1);
        }

        if point2_data[0] & 0x80 != 0 {
            return Ok(1);
        }

        let error_code =
            unsafe { blst::blst_p2_deserialize(&mut blst_g2_list[i], point2_data.as_ptr()) };
        if error_code != blst::BLST_ERROR::BLST_SUCCESS {
            return Ok(1);
        }

        let g2_check = unsafe { blst::blst_p2_affine_in_g2(&blst_g2_list[i]) };
        if g2_check == false {
            return Ok(1);
        }
```
