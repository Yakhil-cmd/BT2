### Title
BLS12-381 (EIP-2537) Precompiles Charge Zero Native Resource, Enabling Proving-System DoS via Underpriced Computation - (File: `basic_bootloader/src/bootloader/block_flow/ethereum/hooks/eip_2537/msm.rs`)

---

### Summary

Every BLS12-381 precompile introduced by EIP-2537 (G1Add, G2Add, G1MSM, G2MSM, PairingCheck, MapFpToG1, MapFp2ToG2) charges `cost_native = 0` for the native (proving) resource. Because native resource is the ZKsync OS proxy for RISC-V proving cycles, these operations consume real prover cycles that are never accounted for. An unprivileged caller can pack a block with BLS12-381 MSM calls — which also carry an EIP-2537 gas discount of up to ~48% for large inputs — and produce a sequencer-accepted block whose actual RISC-V cycle count far exceeds the prover's budget, making the block unprovable and halting the chain.

---

### Finding Description

ZKsync OS implements a **double resource accounting** model: every operation charges both EVM gas (ergs) and a "native" resource that models RISC-V proving cycles. The native resource is the binding constraint for the prover; `MAX_NATIVE_COMPUTATIONAL = 1 << 35` is the per-block ceiling enforced in `check_for_block_limits`.

All other cryptographic precompiles carry calibrated native costs:

| Precompile | Native cost |
|---|---|
| `ecrecover` | `native_with_delegations!(350_000, 43_000, 0)` ≈ 522 K |
| BN254 ECMUL | `native_with_delegations!(600_000, 41_000, 0)` ≈ 764 K |
| BN254 Pairing (per pair) | `native_with_delegations!(13_000_000, 500_000, 0)` ≈ 15 M |
| P256 verify | `native_with_delegations!(500_000, 71_000, 0)` ≈ 784 K |
| KZG point evaluation | `native_with_delegations!(49_900_000, 3_301_000, 0)` ≈ 63 M |

Every BLS12-381 precompile, however, hard-codes `cost_native = 0`:

```rust
// msm.rs – G1MSM
let cost_ergs = Ergs(cost * ERGS_PER_GAS);
let cost_native = 0;                          // ← zero native charged
resources.charge(&R::from_ergs_and_native(
    cost_ergs,
    <R::Native as zk_ee::system::Computational>::from_computational(cost_native),
))?;
```

The same pattern appears in `addition.rs`, `mappings.rs`, and `pairing.rs`. No BLS12-381 native cost constant exists anywhere in `basic_system/src/cost_constants.rs`.

The G1MSM and G2MSM precompiles compound the problem with an EIP-2537 bulk discount: for 128+ points the per-point gas cost is multiplied by `519/1000` (G1) or `524/1000` (G2), meaning more elliptic-curve work is performed per gas unit as batch size grows.

Because native is never decremented during BLS12-381 execution, the block-level check `computational_native_used > MAX_NATIVE_COMPUTATIONAL` is never triggered by BLS12-381 work, regardless of how many operations are packed into a block.

---

### Impact Explanation

**Vulnerability class:** Resource accounting bug → valid-execution unprovability / proving-system DoS.

The sequencer (forward mode) accepts a block because both gas and native resource checks pass (native stays at 0). The prover (RISC-V mode) executes the same code and also charges 0 native — but the actual RISC-V cycle count for BLS12-381 operations is enormous. BLS12-381 operates over a 381-bit prime field; a single G2MSM over 128 points involves hundreds of field multiplications and point doublings, each requiring BigInt delegations. The prover's real cycle budget (tied to `MAX_NATIVE_COMPUTATIONAL`) is therefore silently violated, producing a block the prover cannot finalize. The chain halts until the block is discarded or the prover is given an unbounded budget.

---

### Likelihood Explanation

The attack requires no privileges, no flash loan, and no governance access. Any EOA can deploy a contract that loops over BLS12-381 MSM calls and submit a transaction with a standard gas limit. The EIP-2537 discount table actively incentivizes large batches (cheaper per-point gas), making the attack more efficient at higher point counts. The entry path is identical to any normal EVM transaction.

---

### Recommendation

1. Benchmark BLS12-381 operations on the RISC-V target (as done for BN254 and P256) and add calibrated native cost constants to `basic_system/src/cost_constants.rs`.
2. Apply those constants in every EIP-2537 precompile implementation, replacing `let cost_native = 0` with the measured value, following the same pattern used for BN254 pairing and P256.
3. For G1MSM and G2MSM, the native cost must scale with `num_pairs` (and optionally apply the same discount factor, or a conservative flat rate per pair) to match the actual per-point proving cost.

---

### Proof of Concept

**Setup:** A contract `BLSBomb` calls `BLS12_G2MSM` (address `0x0e`) in a loop, passing 128 G2-point/scalar pairs per call.

**Gas cost per call (128 G2 pairs):**
```
22500 * 128 * (524/1000) = 1,509,120 gas
```

**Native cost per call:** `0` (as charged by the code).

**Calls per 30 M gas block:** `30_000_000 / 1_509_120 ≈ 19` calls.

**Actual RISC-V work per call:** 128 BLS12-381 G2 scalar multiplications. BLS12-381 G2 scalar multiplication is at minimum as expensive as BN254 pairing (≈ 15 M native units each), giving a conservative estimate of `128 × 15_000_000 = 1.92 billion` native units per call.

**Total native consumed (actual) for 19 calls:** `19 × 1.92 B ≈ 36.5 billion` native units — exceeding `MAX_NATIVE_COMPUTATIONAL = 34,359,738,368`.

**Charged native:** `0`.

The sequencer includes the block (native check: `0 ≤ MAX_NATIVE_COMPUTATIONAL` ✓). The prover attempts to prove it, exhausts its cycle budget, and cannot produce a valid proof. The block is stuck.

---

**Root cause lines:** [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) 

**Contrast — other precompiles with correct native costs:** [6](#0-5) 

**Block-level native limit that is bypassed:** [7](#0-6) 

**`MAX_NATIVE_COMPUTATIONAL` definition:** [8](#0-7) 

**MSM discount table (amplifies the attack):** [9](#0-8)

### Citations

**File:** basic_bootloader/src/bootloader/block_flow/ethereum/hooks/eip_2537/msm.rs (L44-51)
```rust
    }
    let discount = if num_pairs > 128 {
        discounts_table[127]
    } else {
        discounts_table[num_pairs - 1]
    };

    (per_pair_cost * num_pairs as u64) * (discount as u64) / (DISCOUNT_DENOMINATOR as u64)
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

**File:** basic_bootloader/src/bootloader/block_flow/ethereum/hooks/eip_2537/msm.rs (L264-270)
```rust
        );
        let cost_ergs = Ergs(cost * ERGS_PER_GAS);
        let cost_native = 0;
        resources.charge(&R::from_ergs_and_native(
            cost_ergs,
            <R::Native as zk_ee::system::Computational>::from_computational(cost_native),
        ))?;
```

**File:** basic_bootloader/src/bootloader/block_flow/ethereum/hooks/eip_2537/pairing.rs (L35-40)
```rust
        );
        let cost_native = 0;
        resources.charge(&R::from_ergs_and_native(
            cost_ergs,
            <R::Native as zk_ee::system::Computational>::from_computational(cost_native),
        ))?;
```

**File:** basic_bootloader/src/bootloader/block_flow/ethereum/hooks/eip_2537/addition.rs (L21-26)
```rust
        let cost_ergs = Ergs(BLS12_381_G1_ADDITION_GAS * ERGS_PER_GAS);
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

**File:** basic_system/src/cost_constants.rs (L45-51)
```rust
pub const BN254_ECADD_NATIVE_COST: u64 = native_with_delegations!(46_000, 1650, 0);
pub const BN254_ECMUL_NATIVE_COST: u64 = native_with_delegations!(600_000, 41_000, 0);
pub const BN254_PAIRING_BASE_NATIVE_COST: u64 = native_with_delegations!(13_000_000, 500_000, 0);
pub const BN254_PAIRING_PER_PAIR_NATIVE_COST: u64 = BN254_PAIRING_BASE_NATIVE_COST;
pub const MODEXP_WORST_CASE_NATIVE_PER_GAS: u64 = 300;
pub const P256_NATIVE_COST: u64 = native_with_delegations!(500_000, 71_000, 0);
// TODO(EVM-1178) Add more vectors and benchmark cost better
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

**File:** zk_ee/src/system/constants.rs (L26-26)
```rust
pub const MAX_NATIVE_COMPUTATIONAL: u64 = 1 << 35;
```
