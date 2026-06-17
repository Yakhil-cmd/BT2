### Title
Blake2F Precompile Charges Zero Native Computational Cost for Arbitrary Round Count, Enabling Prover DoS - (File: `basic_bootloader/src/bootloader/block_flow/ethereum/hooks/eip_152/impls.rs`)

### Summary

The `Blake2FPrecompile` implementation in ZKsync OS hardcodes `cost_native = 0` regardless of the caller-supplied `num_rounds` value (up to `u32::MAX` ≈ 4.3 billion). While ergs (EVM gas) are charged proportionally, the native computational resource — which gates the prover's workload — is never consumed. An attacker who supplies sufficient gas can force the prover to execute billions of Blake2F mixing rounds with zero native resource accounting, causing a prover-level DoS.

### Finding Description

In `Blake2FPrecompile::execute`, the `num_rounds` field is read directly from the first 4 bytes of the 213-byte input as a `u32`:

```rust
let num_rounds = u32::from_be_bytes(input.as_chunks::<4>().0[0]);
let cost_ergs = Ergs(((num_rounds as u64) * GAS_PER_ROUND) * ERGS_PER_GAS);
let cost_native = 0;   // ← hardcoded zero, regardless of num_rounds
resources.charge(&R::from_ergs_and_native(
    cost_ergs,
    <R::Native as zk_ee::system::Computational>::from_computational(cost_native),
))?;
``` [1](#0-0) 

After the charge, the actual mixing function is invoked with the full attacker-controlled count:

```rust
round_function_for_num_rounds(&mut extended_state, &message_block, num_rounds as usize);
``` [2](#0-1) 

The rest of the system correctly assigns non-zero native costs to comparable operations. For example, `BLAKE2S_ROUND_NATIVE_COST = 340` is defined in `cost_constants.rs` but is never applied to the Blake2F precompile: [3](#0-2) 

The transaction-level native resource cap (`MAX_NATIVE_COMPUTATIONAL`) documented in `gas_helpers.rs` provides no protection here because the native cost is never charged — the cap is never approached: [4](#0-3) 

### Impact Explanation

The prover must faithfully execute every round of the Blake2F mixing function to produce a valid proof. With `cost_native = 0`, an attacker can submit a single transaction calling the Blake2F precompile (address `0x0009`) with `num_rounds = 0xFFFFFFFF` (4,294,967,295 rounds), paying only the ergs cost (`num_rounds * 1 gas`). The prover is forced to execute ~4.3 billion mixing iterations per transaction with no native resource budget consumed, exhausting prover CPU and potentially causing a proving-layer DoS. This is a direct analog to the reported RISC-V zkVM SHA ECALL vulnerability where an unbounded `count` parameter exhausted executor resources.

### Likelihood Explanation

The `eip-152` feature flag gates this precompile: [5](#0-4) 

When the feature is enabled (e.g., for EVM-equivalence deployments), the precompile is registered at address `0x0009` and is reachable by any unprivileged transaction sender. The attacker only needs to craft a 213-byte calldata with `num_rounds = 0xFFFFFFFF` in the first 4 bytes and supply sufficient gas. No privileged access is required.

### Recommendation

Charge native cost proportionally to `num_rounds`, mirroring the pattern used for other hash precompiles. Replace the hardcoded `cost_native = 0` with a value derived from `num_rounds` and a per-round native constant (analogous to `BLAKE2S_ROUND_NATIVE_COST`):

```rust
// In impls.rs
pub const NATIVE_COST_PER_ROUND: u64 = /* benchmark-derived constant, e.g. 340 */;

let cost_native = (num_rounds as u64).saturating_mul(NATIVE_COST_PER_ROUND);
resources.charge(&R::from_ergs_and_native(
    cost_ergs,
    <R::Native as zk_ee::system::Computational>::from_computational(cost_native),
))?;
```

This ensures the prover's native resource budget is consumed proportionally to the actual work performed, preventing a single transaction from exhausting prover resources.

### Proof of Concept

1. Enable the `eip-152` feature in the ZKsync OS build.
2. Construct a transaction calling address `0x0000000000000000000000000000000000000009` with the following 213-byte input:
   - Bytes 0–3: `0xFF 0xFF 0xFF 0xFF` (`num_rounds = 4294967295`)
   - Bytes 4–67: any valid 64-byte Blake2b state (e.g., all zeros)
   - Bytes 68–195: any valid 128-byte message block (e.g., all zeros)
   - Bytes 196–203: `t0` counter (e.g., all zeros)
   - Bytes 204–211: `t1` counter (e.g., all zeros)
   - Byte 212: `0x00` (finalization flag = false)
3. Supply `gas = 4294967295 * 1 = ~4.3 billion gas` (or the block gas limit, whichever is lower, to maximize rounds within a single block).
4. Submit the transaction. The prover will attempt to execute ~4.3 billion (or block-gas-limit-capped) rounds of `round_function_for_num_rounds` with zero native resource consumption, causing prover CPU exhaustion.

### Citations

**File:** basic_bootloader/src/bootloader/block_flow/ethereum/hooks/eip_152/impls.rs (L66-72)
```rust
        let num_rounds = u32::from_be_bytes(input.as_chunks::<4>().0[0]);
        let cost_ergs = Ergs(((num_rounds as u64) * GAS_PER_ROUND) * ERGS_PER_GAS);
        let cost_native = 0;
        resources.charge(&R::from_ergs_and_native(
            cost_ergs,
            <R::Native as zk_ee::system::Computational>::from_computational(cost_native),
        ))?;
```

**File:** basic_bootloader/src/bootloader/block_flow/ethereum/hooks/eip_152/impls.rs (L109-109)
```rust
        round_function_for_num_rounds(&mut extended_state, &message_block, num_rounds as usize);
```

**File:** basic_system/src/cost_constants.rs (L34-36)
```rust
pub const BLAKE2S_BASE_NATIVE_COST: u64 = 800;
pub const BLAKE2S_ROUND_NATIVE_COST: u64 = 340;
pub const BLAKE2S_CHUNK_SIZE: usize = 64;
```

**File:** basic_bootloader/src/bootloader/transaction_flow/gas_helpers.rs (L174-178)
```rust
pub struct ResourcesForTx<S: EthereumLikeTypes> {
    // Resources to run the transaction.
    // These will be capped to MAX_NATIVE_COMPUTATIONAL, to prevent
    // transaction from using too many native computational resources.
    pub main_resources: S::Resources,
```

**File:** evm_interpreter/src/precompile_addresses.rs (L9-10)
```rust
#[cfg(any(feature = "eip-152", feature = "mock-unsupported-precompiles"))]
pub const BLAKE2F_HOOK_ADDRESS_LOW: u16 = 0x0009;
```
