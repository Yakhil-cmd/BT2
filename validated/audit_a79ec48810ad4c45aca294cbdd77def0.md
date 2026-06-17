### Title
BLS12-381 MSM and Pairing Precompiles Charge Zero Native Resource for Unbounded Per-Pair Loop — (`File: basic_bootloader/src/bootloader/block_flow/ethereum/hooks/eip_2537/msm.rs`, `pairing.rs`)

---

### Summary

The EIP-2537 BLS12-381 precompiles (`G1MSM`, `G2MSM`, `PairingCheck`) execute an unbounded loop over attacker-controlled input pairs while charging `cost_native = 0` for the entire computation. EVM gas is charged proportionally to `num_pairs`, but the **native resource** (RISC-V proving cycles) is never decremented for the actual elliptic-curve work. This creates a forward/proving divergence: a transaction that succeeds in forward execution can exhaust the prover's actual cycle budget, making the block unprovable.

---

### Finding Description

In `Bls12381G1MSMPrecompile::execute` and `Bls12381G2MSMPrecompile::execute`, the resource charge is:

```rust
let cost_ergs = Ergs(cost * ERGS_PER_GAS);
let cost_native = 0;                          // ← zero native charge
resources.charge(&R::from_ergs_and_native(
    cost_ergs,
    <R::Native as zk_ee::system::Computational>::from_computational(cost_native),
))?;
``` [1](#0-0) 

After this single upfront charge, the code enters an unbounded loop over all `num_pairs` input pairs, performing a full BLS12-381 G1 (or G2) subgroup check and scalar parse per pair, then calls the Pippenger MSM algorithm whose inner loop is `O(num_pairs × NUM_BITS/c)` elliptic-curve group additions:

```rust
for pair_encoding in input.as_chunks::<G1_MSM_PAIR_LEN>().0.iter() {
    let point = parse_g1_with_subgroup_check(...)?;   // field ops per pair
    let scalar = parse_integer(...);
    points.push(point);
    scalars.push(scalar);
}
let result: G1Projective = msm(&points, scalars, allocator);
``` [2](#0-1) 

Inside `msm()`, the Pippenger loop iterates `num_windows × num_pairs` times with group additions:

```rust
for window_idx in 0..num_windows {
    for i in 0..bases.len() {          // ← scales with num_pairs
        reusable_buckets[(scalar - 1) as usize] += &bases[i];
    }
    for el in reusable_buckets.iter_mut().rev() { ... }
}
``` [3](#0-2) 

The same `cost_native = 0` pattern appears in `Bls12381PairingCheckPrecompile::execute`, which also loops over all pairs calling `multi_pairing`: [4](#0-3) 

The double resource accounting model explicitly states that native resource models RISC-V proving cycles and must be charged for all computation: [5](#0-4) 

The native resource limit is `nativeLimit = gasLimit × nativePerGas`. Because `cost_native = 0`, the entire proving cost of the MSM/pairing loop is invisible to the native resource counter. The EVM gas charge is proportional to `num_pairs` with a discount table that caps at ~51.9% for large `n`, meaning the EVM gas cost grows sub-linearly while the actual RISC-V cycle cost grows super-linearly (Pippenger is `O(n / log n)` group operations, each costing hundreds of field multiplications on RISC-V).

---

### Impact Explanation

**Vulnerability class**: Resource accounting bug → valid-execution unprovability / forward-proving divergence.

An attacker submits a transaction calling `BLS12_G1MSM` (address `0x0c`) or `BLS12_G2MSM` (address `0x0e`) with the maximum number of pairs that fit within the block gas limit. The forward system (sequencer) accepts the transaction because EVM gas is charged correctly and native resource is not exhausted (it was never charged for the MSM work). The block is sealed and committed. When the prover attempts to generate a ZK proof, the actual RISC-V cycle count for the MSM far exceeds the native resource budget implied by the transaction's gas parameters, making the block unprovable. This stalls the rollup's proof pipeline.

---

### Likelihood Explanation

The EIP-2537 precompiles are enabled in the Ethereum block runner path (`initialize_eip_2537` is called unconditionally). Any unprivileged EOA can call `0x0c` (G1MSM) or `0x0e` (G2MSM) directly. The attacker only needs to submit a transaction with a high gas limit and a large MSM input. No special role, governance access, or oracle manipulation is required. The `G1_MSM_PAIR_LEN` is 160 bytes; at a 30M gas block limit and 12,000 gas per pair (with discount ~519/1000 for large n), an attacker can pack thousands of pairs into a single transaction. [6](#0-5) 

---

### Recommendation

Assign a non-zero `cost_native` proportional to `num_pairs` for G1MSM, G2MSM, and PairingCheck. Profile the actual RISC-V cycle cost per BLS12-381 group addition and field multiplication on the target `riscv32i` ISA, then set:

```rust
let cost_native = NATIVE_COST_PER_BLS_PAIR * num_pairs as u64;
resources.charge(&R::from_ergs_and_native(
    cost_ergs,
    <R::Native as zk_ee::system::Computational>::from_computational(cost_native),
))?;
```

This mirrors the pattern used for storage operations, which charge both ergs and native resource per access.

---

### Proof of Concept

1. Deploy no contract; call precompile `0x0c` (BLS12_G1MSM) directly.
2. Construct calldata as `N` repetitions of a valid G1 point (128 bytes) concatenated with a 32-byte scalar — total `N × 160` bytes.
3. Set `gas_limit` to the block gas limit (e.g., 30,000,000). At 12,000 gas/pair × 0.519 discount ≈ 6,228 gas/pair effective, this allows ~4,800 pairs.
4. Submit the transaction. Forward execution succeeds: EVM gas is consumed, native resource counter is barely touched (only the ergs→native conversion applies, not the MSM work itself).
5. The prover must execute ~4,800 BLS12-381 G1 scalar multiplications on RISC-V, each requiring thousands of 256-bit field multiplications. The actual cycle count vastly exceeds `nativeLimit`, causing the prover to fail or diverge from the forward execution result. [7](#0-6) [8](#0-7)

### Citations

**File:** basic_bootloader/src/bootloader/block_flow/ethereum/hooks/eip_2537/msm.rs (L6-9)
```rust
pub const BLS12_381_G1_MSM_PER_POINT_GAS: u64 = 12000;
pub const BLS12_381_G2_MSM_PER_POINT_GAS: u64 = 22500;

pub const G1_MSM_PAIR_LEN: usize = SCALAR_SERIALIZATION_LEN + G1_SERIALIZATION_LEN;
```

**File:** basic_bootloader/src/bootloader/block_flow/ethereum/hooks/eip_2537/msm.rs (L123-155)
```rust
    for window_idx in 0..num_windows {
        let last_window = window_idx == num_windows - 1;

        unsafe {
            core::hint::assert_unchecked(bases.len() == bigints.len());
        }
        for i in 0..bases.len() {
            let bigint = &mut bigints[i];
            // get window
            let scalar: u64 = bigint.as_ref()[0] & lowest_bits_mask;

            use core::ops::ShrAssign;
            bigint.shr_assign(c as u32);

            if scalar != 0 {
                reusable_buckets[(scalar - 1) as usize] += &bases[i];
            }
        }

        // now sum over buckets
        let mut tmp = zero;
        let mut window_result = zero;
        for el in reusable_buckets.iter_mut().rev() {
            tmp += &*el;
            window_result += &tmp;
            if last_window == false {
                *el = zero;
            }
        }
        window_sums[window_idx] = window_result;

        window_start += c;
    }
```

**File:** basic_bootloader/src/bootloader/block_flow/ethereum/hooks/eip_2537/msm.rs (L191-202)
```rust
        let cost = compute_cost(
            input.len(),
            G1_MSM_PAIR_LEN,
            BLS12_381_G1_MSM_PER_POINT_GAS,
            &DISCOUNT_TABLE_G1_MSM,
        );
        let cost_ergs = Ergs(cost * ERGS_PER_GAS);
        let cost_native = 0;
        resources.charge(&R::from_ergs_and_native(
            cost_ergs,
            <R::Native as zk_ee::system::Computational>::from_computational(cost_native),
        ))?;
```

**File:** basic_bootloader/src/bootloader/block_flow/ethereum/hooks/eip_2537/msm.rs (L218-232)
```rust
        for pair_encoding in input.as_chunks::<G1_MSM_PAIR_LEN>().0.iter() {
            let point = parse_g1_with_subgroup_check(
                pair_encoding[0..G1_SERIALIZATION_LEN].try_into().unwrap(),
            )?;
            let scalar = parse_integer(
                pair_encoding
                    [G1_SERIALIZATION_LEN..(G1_SERIALIZATION_LEN + SCALAR_SERIALIZATION_LEN)]
                    .try_into()
                    .unwrap(),
            );
            points.push(point);
            scalars.push(scalar);
        }

        let result: G1Projective = msm(&points, scalars, allocator);
```

**File:** basic_bootloader/src/bootloader/block_flow/ethereum/hooks/eip_2537/msm.rs (L259-270)
```rust
        let cost = compute_cost(
            input.len(),
            G2_MSM_PAIR_LEN,
            BLS12_381_G2_MSM_PER_POINT_GAS,
            &DISCOUNT_TABLE_G2_MSM,
        );
        let cost_ergs = Ergs(cost * ERGS_PER_GAS);
        let cost_native = 0;
        resources.charge(&R::from_ergs_and_native(
            cost_ergs,
            <R::Native as zk_ee::system::Computational>::from_computational(cost_native),
        ))?;
```

**File:** basic_bootloader/src/bootloader/block_flow/ethereum/hooks/eip_2537/pairing.rs (L36-40)
```rust
        let cost_native = 0;
        resources.charge(&R::from_ergs_and_native(
            cost_ergs,
            <R::Native as zk_ee::system::Computational>::from_computational(cost_native),
        ))?;
```

**File:** docs/double_resource_accounting.md (L17-19)
```markdown
The native resource models the offchain cost of processing a transaction. Currently, this is dominated by proving and publishing data. A good intuition for it is "how many RISC-V cycles it takes to prove a given computation".

If a transaction execution runs out of native resources, the entire transaction is reverted. If the same happens during transaction validation, the transaction is considered invalid.
```
