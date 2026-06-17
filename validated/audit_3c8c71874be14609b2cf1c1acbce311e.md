### Title
BLS12-381 EIP-2537 Precompiles Use Hardcoded `cost_native = 0` for All Operations — (`basic_bootloader/src/bootloader/block_flow/ethereum/hooks/eip_2537/`)

### Summary
All seven BLS12-381 EIP-2537 precompiles hardcode `cost_native = 0`, charging zero native (proving) resources regardless of the actual computational complexity of each operation. This is the direct analog of the UniswapV3 pool-fee bug: a single fixed parameter is applied uniformly across all operations when it must vary per-operation to correctly model cost.

### Finding Description
ZKsync OS uses a **double resource accounting** model: EVM gas (ergs) and a **native resource** that models RISC-V proving cycles. Every operation that consumes proving cycles must charge an appropriate native cost so that the forward execution model stays aligned with the prover's actual work.

All seven BLS12-381 precompiles hardcode `cost_native = 0`:

`addition.rs` — G1Add: [1](#0-0) 

`addition.rs` — G2Add: [2](#0-1) 

`msm.rs` — G1MSM: [3](#0-2) 

`msm.rs` — G2MSM: [4](#0-3) 

`pairing.rs` — PairingCheck: [5](#0-4) 

`mappings.rs` — MapFpToG1 and MapFp2ToG2: [6](#0-5) 

By contrast, every other cryptographic precompile carries a non-zero, operation-specific native cost: [7](#0-6) 

BLS12-381 operations are substantially more expensive than BN254 operations (larger field, more Miller-loop iterations, larger MSM scalars). `BN254_PAIRING_BASE_NATIVE_COST` alone is `native_with_delegations!(13_000_000, 500_000, 0)`, yet the BLS12-381 pairing check charges `0`.

The native resource model is documented as:

> "The native resource models the offchain cost of processing a transaction. Currently, this is dominated by proving and publishing data." [8](#0-7) 

### Impact Explanation
**Impact: Medium — resource accounting divergence / DoS of the proving pipeline.**

1. **Forward/proving divergence.** Forward execution charges `0` native units for BLS12-381 calls. The prover must still spend real RISC-V cycles to verify them. A block that passes forward execution with native budget intact can require far more proving cycles than the budget implies, breaking the invariant that `nativeLimit ≥ actual proving cost`.

2. **Proving-pipeline DoS.** An unprivileged caller can pack a block with BLS12-381 MSM or pairing calls (e.g., G2MSM with hundreds of pairs, each pair costing `0` native) and exhaust the prover's real cycle budget without exhausting the on-chain native limit. This is directly reachable: no privileged role is required, only a transaction calling address `0x0c`–`0x11`.

3. **Economic under-charging.** Users pay only EVM gas for BLS12-381 work; the native component — which is what the operator charges for proving — is never collected, creating a subsidy that can be exploited at scale.

### Likelihood Explanation
**Likelihood: Medium.** The `eip-2537` feature must be compiled in (it is listed as a supported feature in the codebase). Once enabled, any EOA or contract can call the BLS12-381 precompile addresses (`0x0b`–`0x11`) directly with no access control. The attacker only needs to submit a transaction with large MSM or pairing inputs; no leaked keys, governance majority, or oracle manipulation is required. [9](#0-8) 

### Recommendation
Add per-operation native cost constants for all BLS12-381 precompiles, following the same pattern used for BN254:

```rust
// Example (values must be benchmarked on the RISC-V target):
pub const BLS12_381_G1_ADD_NATIVE_COST: u64 = native_with_delegations!(…);
pub const BLS12_381_PAIRING_BASE_NATIVE_COST: u64 = native_with_delegations!(…);
// etc.
```

Replace every `cost_native = 0` with the appropriate benchmarked constant before enabling EIP-2537 in production.

### Proof of Concept
1. Enable the `eip-2537` feature.
2. Submit a transaction calling `BLS12_G2MSM` (address `0x0e`) with 128 valid G2-point/scalar pairs — the EVM gas cost is bounded by the MSM discount table, but `cost_native = 0` means the native budget is untouched.
3. Observe that forward execution succeeds and the native resource counter is unchanged despite hundreds of field-multiplication rounds.
4. The prover must execute the full MSM computation in RISC-V, consuming real cycles that were never accounted for in the native limit, causing the block's actual proving cost to exceed what the transaction paid for.

### Citations

**File:** basic_bootloader/src/bootloader/block_flow/ethereum/hooks/eip_2537/addition.rs (L21-26)
```rust
        let cost_ergs = Ergs(BLS12_381_G1_ADDITION_GAS * ERGS_PER_GAS);
        let cost_native = 0;
        resources.charge(&R::from_ergs_and_native(
            cost_ergs,
            <R::Native as zk_ee::system::Computational>::from_computational(cost_native),
        ))?;
```

**File:** basic_bootloader/src/bootloader/block_flow/ethereum/hooks/eip_2537/addition.rs (L62-67)
```rust
        let cost_ergs = Ergs(BLS12_381_G2_ADDITION_GAS * ERGS_PER_GAS);
        let cost_native = 0;
        resources.charge(&R::from_ergs_and_native(
            cost_ergs,
            <R::Native as zk_ee::system::Computational>::from_computational(cost_native),
        ))?;
```

**File:** basic_bootloader/src/bootloader/block_flow/ethereum/hooks/eip_2537/msm.rs (L197-202)
```rust
        let cost_ergs = Ergs(cost * ERGS_PER_GAS);
        let cost_native = 0;
        resources.charge(&R::from_ergs_and_native(
            cost_ergs,
            <R::Native as zk_ee::system::Computational>::from_computational(cost_native),
        ))?;
```

**File:** basic_bootloader/src/bootloader/block_flow/ethereum/hooks/eip_2537/msm.rs (L265-270)
```rust
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

**File:** basic_bootloader/src/bootloader/block_flow/ethereum/hooks/eip_2537/mappings.rs (L25-30)
```rust
        let cost_ergs = Ergs(BLS12_381_FIELD_TO_G1_GAS * ERGS_PER_GAS);
        let cost_native = 0;
        resources.charge(&R::from_ergs_and_native(
            cost_ergs,
            <R::Native as zk_ee::system::Computational>::from_computational(cost_native),
        ))?;
```

**File:** basic_system/src/cost_constants.rs (L22-50)
```rust
pub const ECRECOVER_NATIVE_COST: u64 = native_with_delegations!(350_000, 43_000, 0);
pub const KECCAK256_BASE_NATIVE_COST: u64 = 2_500;
pub const KECCAK256_ROUND_NATIVE_COST: u64 = 17_500;
pub const KECCAK256_CHUNK_SIZE: usize = 136;
pub const SHA256_BASE_NATIVE_COST: u64 = 1_600;
pub const SHA256_ROUND_NATIVE_COST: u64 = 4_200;
pub const SHA256_CHUNK_SIZE: usize = 64;
pub const RIPEMD160_BASE_NATIVE_COST: u64 = 1_600;
pub const RIPEMD160_ROUND_NATIVE_COST: u64 = 4_200;
pub const RIPEMD160_CHUNK_SIZE: usize = 64;
/// Native costs for blake2s hashing.
/// NOTE: To recompute if the blake coefficient changes.
pub const BLAKE2S_BASE_NATIVE_COST: u64 = 800;
pub const BLAKE2S_ROUND_NATIVE_COST: u64 = 340;
pub const BLAKE2S_CHUNK_SIZE: usize = 64;

/// Helper to compute blake2s hashing native cost for a given input length.
pub const fn blake2s_native_cost(len: usize) -> u64 {
    let num_rounds = len.div_ceil(BLAKE2S_CHUNK_SIZE) as u64;
    num_rounds
        .saturating_mul(BLAKE2S_ROUND_NATIVE_COST)
        .saturating_add(BLAKE2S_BASE_NATIVE_COST)
}
pub const BN254_ECADD_NATIVE_COST: u64 = native_with_delegations!(46_000, 1650, 0);
pub const BN254_ECMUL_NATIVE_COST: u64 = native_with_delegations!(600_000, 41_000, 0);
pub const BN254_PAIRING_BASE_NATIVE_COST: u64 = native_with_delegations!(13_000_000, 500_000, 0);
pub const BN254_PAIRING_PER_PAIR_NATIVE_COST: u64 = BN254_PAIRING_BASE_NATIVE_COST;
pub const MODEXP_WORST_CASE_NATIVE_PER_GAS: u64 = 300;
pub const P256_NATIVE_COST: u64 = native_with_delegations!(500_000, 71_000, 0);
```

**File:** docs/double_resource_accounting.md (L15-19)
```markdown
## Native resource

The native resource models the offchain cost of processing a transaction. Currently, this is dominated by proving and publishing data. A good intuition for it is "how many RISC-V cycles it takes to prove a given computation".

If a transaction execution runs out of native resources, the entire transaction is reverted. If the same happens during transaction validation, the transaction is considered invalid.
```

**File:** basic_bootloader/src/bootloader/block_flow/ethereum/hooks/eip_2537/mod.rs (L37-72)
```rust
pub fn initialize_eip_2537<S: EthereumLikeTypes>(
    hooks: &mut HooksStorage<S, S::Allocator>,
) -> Result<(), InternalError>
where
    S::IO: IOSubsystemExt,
{
    add_precompile::<S, S::Allocator, Bls12381G1AdditionPrecompile, Bls12PrecompileErrors>(
        hooks,
        BLS12_G1ADD,
    )?;
    add_precompile::<S, S::Allocator, Bls12381G2AdditionPrecompile, Bls12PrecompileErrors>(
        hooks,
        BLS12_G2ADD,
    )?;
    add_precompile::<S, S::Allocator, Bls12381G1MSMPrecompile, Bls12PrecompileErrors>(
        hooks,
        BLS12_G1MSM,
    )?;
    add_precompile::<S, S::Allocator, Bls12381G2MSMPrecompile, Bls12PrecompileErrors>(
        hooks,
        BLS12_G2MSM,
    )?;
    add_precompile::<S, S::Allocator, Bls12381PairingCheckPrecompile, Bls12PrecompileErrors>(
        hooks,
        BLS12_PAIRING_CHECK,
    )?;
    add_precompile::<S, S::Allocator, Bls12381G1MappingPrecompile, Bls12PrecompileErrors>(
        hooks,
        BLS12_MAP_FP_TO_G1,
    )?;
    add_precompile::<S, S::Allocator, Bls12381G2MappingPrecompile, Bls12PrecompileErrors>(
        hooks,
        BLS12_MAP_FP2_TO_G2,
    )?;
    Ok(())
}
```
