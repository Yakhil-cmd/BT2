### Title
Zero Native Resource Charge for All EIP-2537 BLS12-381 Precompiles Enables Prover Resource Exhaustion - (File: `basic_bootloader/src/bootloader/block_flow/ethereum/hooks/eip_2537/msm.rs`, `addition.rs`, `mappings.rs`, `pairing.rs`)

---

### Summary

All six EIP-2537 BLS12-381 precompile implementations hardcode `cost_native = 0`, meaning they charge **zero** native resources regardless of input size or computational complexity. Native resources model the off-chain proving cost (RISC-V cycles). By contrast, BN254 precompiles correctly charge a non-zero `BN254_ECADD_NATIVE_COST`. An unprivileged transaction sender can invoke the most expensive BLS12-381 operations (G2 MSM, Pairing) with maximum-size inputs, consuming substantial prover cycles while paying only EVM gas (ergs), not the native resource that gates proving budget.

---

### Finding Description

Every EIP-2537 precompile sets `cost_native = 0` before calling `resources.charge(...)`:

**G1 MSM** and **G2 MSM** (`msm.rs`): [1](#0-0) 

**G1 Addition** and **G2 Addition** (`addition.rs`): [2](#0-1) 

**G1 Mapping** and **G2 Mapping** (`mappings.rs`): [3](#0-2) 

**Pairing** (`pairing.rs`): [4](#0-3) 

Compare this to the BN254 `ecadd` precompile, which correctly charges a non-zero `BN254_ECADD_NATIVE_COST`: [5](#0-4) 

The ZKsync OS documentation explicitly states that native resources model the off-chain proving cost and that running out of native resources reverts the transaction: [6](#0-5) 

The `nativePerGas` ratio is derived from `gasPrice / nativePrice`, so a transaction with a low gas price (e.g., at base fee only) will have a low `nativePerGas` and a correspondingly low native budget. However, since BLS12-381 precompiles never consume any native budget, the native limit is never approached through these calls, regardless of how many times they are invoked within a single transaction.

---

### Impact Explanation

BLS12-381 operations — especially G2 MSM with 128 pairs and multi-pairing — are among the most computationally intensive precompiles in the EVM. A G2 MSM with 128 pairs costs `22500 * 128 * (524/1000) ≈ 1,509,120` EVM gas in ergs, but **zero** native resources. An attacker can craft a transaction that fills its entire EVM gas budget with back-to-back BLS12-381 calls, consuming a disproportionate amount of prover cycles relative to the native resource budget they paid for. This breaks the invariant that native resources gate proving cost, potentially allowing a single transaction to impose proving costs far exceeding what the fee model accounts for. The result is a **resource accounting bug** that can be used to grief the prover or degrade block throughput.

---

### Likelihood Explanation

Any unprivileged EOA or contract can call BLS12-381 precompile addresses. No special role, governance access, or oracle manipulation is required. The attacker only needs to submit a standard transaction with sufficient EVM gas. The attack is repeatable across blocks.

---

### Recommendation

Assign a non-zero `cost_native` to each EIP-2537 precompile, proportional to its actual proving cost, following the same pattern used for BN254 precompiles (e.g., `BN254_ECADD_NATIVE_COST` in `cost_constants.rs`). Define per-operation constants such as `BLS12_381_G1_MSM_NATIVE_COST_PER_PAIR`, `BLS12_381_G2_MSM_NATIVE_COST_PER_PAIR`, `BLS12_381_PAIRING_NATIVE_COST_PER_PAIR`, etc., calibrated against actual RISC-V cycle measurements for each operation. Apply these in the `resources.charge(...)` call in each precompile's `execute` function.

---

### Proof of Concept

1. Deploy or use an existing contract that calls the BLS12-381 G2 MSM precompile (EIP-2537 address) with 128 G2/scalar pairs in a loop.
2. Submit a transaction with a gas limit of, say, 30,000,000 and a gas price at base fee only (zero priority fee, so `nativePerGas` is minimal).
3. Observe that the transaction executes successfully, consuming ~1.5M gas per MSM call (≈20 calls per 30M gas block), while charging **zero** native resources per call.
4. The prover must process all 20 × 128 = 2,560 G2 MSM pairs at full proving cost, but the native resource budget was never touched — the fee model did not account for this proving work.

The root cause is the hardcoded `cost_native = 0` at: [7](#0-6) [8](#0-7) [9](#0-8)

### Citations

**File:** basic_bootloader/src/bootloader/block_flow/ethereum/hooks/eip_2537/msm.rs (L197-202)
```rust
        let cost_ergs = Ergs(cost * ERGS_PER_GAS);
        let cost_native = 0;
        resources.charge(&R::from_ergs_and_native(
            cost_ergs,
            <R::Native as zk_ee::system::Computational>::from_computational(cost_native),
        ))?;
```

**File:** basic_bootloader/src/bootloader/block_flow/ethereum/hooks/eip_2537/msm.rs (L266-266)
```rust
        let cost_native = 0;
```

**File:** basic_bootloader/src/bootloader/block_flow/ethereum/hooks/eip_2537/addition.rs (L22-26)
```rust
        let cost_native = 0;
        resources.charge(&R::from_ergs_and_native(
            cost_ergs,
            <R::Native as zk_ee::system::Computational>::from_computational(cost_native),
        ))?;
```

**File:** basic_bootloader/src/bootloader/block_flow/ethereum/hooks/eip_2537/mappings.rs (L26-30)
```rust
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

**File:** basic_system/src/system_functions/bn254_ecadd.rs (L49-52)
```rust
    resources.charge(&R::from_ergs_and_native(
        BN254_ECADD_COST_ERGS,
        <R::Native as zk_ee::system::Computational>::from_computational(BN254_ECADD_NATIVE_COST),
    ))?;
```

**File:** docs/double_resource_accounting.md (L17-19)
```markdown
The native resource models the offchain cost of processing a transaction. Currently, this is dominated by proving and publishing data. A good intuition for it is "how many RISC-V cycles it takes to prove a given computation".

If a transaction execution runs out of native resources, the entire transaction is reverted. If the same happens during transaction validation, the transaction is considered invalid.
```
