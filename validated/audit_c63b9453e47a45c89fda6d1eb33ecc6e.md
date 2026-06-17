### Title
Native Resource Not Charged for BLS12-381 Pairing Precompile Unbounded Loop Over User-Controlled Pairs - (File: `basic_bootloader/src/bootloader/block_flow/ethereum/hooks/eip_2537/pairing.rs`)

---

### Summary

The BLS12-381 pairing precompile (`Bls12381PairingCheckPrecompile`) iterates over a user-controlled number of elliptic-curve pairs derived from the calldata length, performing expensive G1/G2 deserialization, subgroup membership checks, and a multi-pairing computation per pair. However, the native resource cost (which models RISC-V proving cycles) is hardcoded to `0`, meaning the prover must perform O(N) cryptographic work without any native resource being consumed. This is a direct analog to the DyDx unbounded-loop resource exhaustion class: a loop bounded only by user-supplied input length, with no proportional resource accounting for the actual work performed.

---

### Finding Description

In `Bls12381PairingCheckPrecompile::execute`:

```rust
let num_pairs = input.len() / BLS12_381_PAIR_LEN;
let cost_ergs = Ergs(
    ((num_pairs as u64) * BLS12_381_PAIRING_PER_PAIR_GAS + BLS12_381_PAIRING_FIXED_GAS)
        * ERGS_PER_GAS,
);
let cost_native = 0;   // ← hardcoded zero
resources.charge(&R::from_ergs_and_native(
    cost_ergs,
    <R::Native as zk_ee::system::Computational>::from_computational(cost_native),
))?;
``` [1](#0-0) 

After charging, the function loops over every pair:

```rust
for pair_encoding in input.as_chunks::<BLS12_381_PAIR_LEN>().0.iter() {
    let g1 = parse_g1_with_subgroup_check(...)?;
    let g2 = parse_g2_with_subgroup_check(...)?;
    g1_points.push(g1);
    g2_points.push(g2);
}
let pairing_result = <Bls12_381 as Pairing>::multi_pairing(g1_points, g2_points);
``` [2](#0-1) 

Each iteration performs G1 and G2 subgroup membership checks (expensive field arithmetic), and the final `multi_pairing` call is O(N) in the number of pairs. All of this work is done with `cost_native = 0`.

Contrast this with the BN254 pairing precompile, which correctly charges a large native cost per pair:

```rust
pub const BN254_PAIRING_BASE_NATIVE_COST: u64 = native_with_delegations!(13_000_000, 500_000, 0);
pub const BN254_PAIRING_PER_PAIR_NATIVE_COST: u64 = BN254_PAIRING_BASE_NATIVE_COST;
``` [3](#0-2) 

And the BN254 pairing charges it proportionally:

```rust
let native_cost = (num_pairs as u64) * BN254_PAIRING_PER_PAIR_NATIVE_COST
    + BN254_PAIRING_BASE_NATIVE_COST;
resources.charge(&R::from_ergs_and_native(ergs_cost, ...native_cost...))?;
``` [4](#0-3) 

The BLS12-381 precompile has no equivalent native accounting.

---

### Impact Explanation

ZKsync OS uses a dual-resource model: EVM gas (ergs) and native resource (RISC-V proving cycles). The native resource is the critical bound for provability. [5](#0-4) 

Because `cost_native = 0` for BLS12-381 pairing:

1. **Forward/proving divergence**: Forward execution succeeds and consumes 0 native resource. The prover must actually execute the BLS12-381 multi-pairing (O(N) field operations), consuming real RISC-V cycles. If the block's native resource budget is tight, the prover exhausts native resources and the block becomes unprovable — a valid-execution-unprovability scenario.

2. **Resource accounting bug**: A transaction can force the prover to perform arbitrarily large BLS12-381 pairing work (bounded only by EVM gas, not native resource). The native resource budget is not consumed, so the block-level native limit (`MAX_NATIVE_COMPUTATIONAL`) does not protect against this. [6](#0-5) 

---

### Likelihood Explanation

Any unprivileged transaction sender can call the BLS12-381 pairing precompile (EIP-2537, address `0x0f`) with a large input. The EVM gas cost is charged proportionally (`num_pairs * 32600 + 37700` gas), so the number of pairs is bounded by the transaction gas limit. However, since native cost is 0, the prover must do O(N) work for free. With a 30M gas block limit, an attacker can force up to ~920 pairs per transaction, each requiring expensive G1/G2 subgroup checks and a multi-pairing computation — all at zero native cost. This is directly reachable with no privileged access.

---

### Recommendation

Assign a non-zero, proportional native cost to the BLS12-381 pairing precompile, mirroring the BN254 pairing pattern. Benchmark the actual RISC-V cycle cost of `parse_g1_with_subgroup_check`, `parse_g2_with_subgroup_check`, and `multi_pairing` per pair, then set:

```rust
pub const BLS12_381_PAIRING_BASE_NATIVE_COST: u64 = native_with_delegations!(...);
pub const BLS12_381_PAIRING_PER_PAIR_NATIVE_COST: u64 = ...;

let cost_native = (num_pairs as u64) * BLS12_381_PAIRING_PER_PAIR_NATIVE_COST
    + BLS12_381_PAIRING_BASE_NATIVE_COST;
```

---

### Proof of Concept

1. Deploy a contract that calls the BLS12-381 pairing precompile at address `0x0f` with `K * BLS12_381_PAIR_LEN` bytes of valid (or zero-padded) input, where `K` is chosen to consume most of the transaction's EVM gas budget.
2. Submit the transaction with a high gas limit (e.g., 10M gas → ~300 pairs).
3. Observe in forward execution: native resource consumed = 0 (regardless of K).
4. Observe in proving: the prover must execute `K` iterations of G1/G2 subgroup checks plus `multi_pairing`, consuming real RISC-V cycles proportional to K.
5. If K is large enough relative to the block's remaining native budget, the prover exhausts native resources and the block cannot be proven, despite forward execution succeeding — a forward/proving divergence. [7](#0-6)

### Citations

**File:** basic_bootloader/src/bootloader/block_flow/ethereum/hooks/eip_2537/pairing.rs (L26-45)
```rust
        if input.len() == 0 {
            return Err(interface_error!(
                Bls12PrecompileInterfaceError::InvalidInputSize
            ));
        }
        let num_pairs = input.len() / BLS12_381_PAIR_LEN;
        let cost_ergs = Ergs(
            ((num_pairs as u64) * BLS12_381_PAIRING_PER_PAIR_GAS + BLS12_381_PAIRING_FIXED_GAS)
                * ERGS_PER_GAS,
        );
        let cost_native = 0;
        resources.charge(&R::from_ergs_and_native(
            cost_ergs,
            <R::Native as zk_ee::system::Computational>::from_computational(cost_native),
        ))?;

        if !input.len().is_multiple_of(BLS12_381_PAIR_LEN) {
            return Err(interface_error!(
                Bls12PrecompileInterfaceError::InvalidInputSize
            ));
```

**File:** basic_bootloader/src/bootloader/block_flow/ethereum/hooks/eip_2537/pairing.rs (L55-68)
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

        let pairing_result = <Bls12_381 as Pairing>::multi_pairing(g1_points, g2_points);
```

**File:** basic_system/src/cost_constants.rs (L47-48)
```rust
pub const BN254_PAIRING_BASE_NATIVE_COST: u64 = native_with_delegations!(13_000_000, 500_000, 0);
pub const BN254_PAIRING_PER_PAIR_NATIVE_COST: u64 = BN254_PAIRING_BASE_NATIVE_COST;
```

**File:** basic_system/src/system_functions/bn254_pairing_check.rs (L34-43)
```rust
            let num_pairs = src.len() / 192;
            let ergs_cost = BN254_PAIRING_STATIC_COST_ERGS
                + BN254_PAIRING_COST_PER_PAIR_ERGS.times(num_pairs as u64);
            let native_cost = (num_pairs as u64) * BN254_PAIRING_PER_PAIR_NATIVE_COST
                + BN254_PAIRING_BASE_NATIVE_COST;

            resources.charge(&R::from_ergs_and_native(
                ergs_cost,
                <R::Native as zk_ee::system::Computational>::from_computational(native_cost),
            ))?;
```

**File:** docs/double_resource_accounting.md (L15-21)
```markdown
## Native resource

The native resource models the offchain cost of processing a transaction. Currently, this is dominated by proving and publishing data. A good intuition for it is "how many RISC-V cycles it takes to prove a given computation".

If a transaction execution runs out of native resources, the entire transaction is reverted. If the same happens during transaction validation, the transaction is considered invalid.

The native resources are passed fully from frame to frame, a call cannot set a limit on how much of it the callee can spend.
```

**File:** basic_bootloader/src/bootloader/block_flow/zk/mod.rs (L68-77)
```rust
    } else if !cfg!(feature = "resources_for_tester")
        && computational_native_used > MAX_NATIVE_COMPUTATIONAL
    {
        // ZKsync OS-specific resources are not checked for evm tester
        system_log!(
            system,
            "Block native limit reached, invalidating transaction\n"
        );
        Err(InvalidTransaction::BlockNativeLimitReached)
    } else if !cfg!(feature = "resources_for_tester") && pubdata_used > system.get_pubdata_limit() {
```
