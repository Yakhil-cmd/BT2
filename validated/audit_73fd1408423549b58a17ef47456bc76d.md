### Title
Forward/Proving Divergence via Disabled EOA Signature Validation in Sequencer Forward Run — (`basic_bootloader/src/bootloader/config.rs`, `forward_system/src/run/mod.rs`)

---

### Summary

The production sequencer's `run_block` entry point uses `BasicBootloaderForwardSimulationConfig`, which sets `VALIDATE_EOA_SIGNATURE: false`. Both the ZK and Ethereum-like validation paths gate the entire ecrecover/signature-check branch on this flag. The prover uses `BasicBootloaderProvingExecutionConfig` with `VALIDATE_EOA_SIGNATURE: true`. An unprivileged sender can submit a transaction bearing an arbitrary or forged signature; the sequencer executes it without complaint, but the prover rejects it, producing a block that is valid in the forward run but unprovable — a classic forward/proving divergence.

---

### Finding Description

`BasicBootloaderForwardSimulationConfig` is the config used by the production sequencer's `run_block`: [1](#0-0) 

```rust
impl BasicBootloaderExecutionConfig for BasicBootloaderForwardSimulationConfig {
    const VALIDATE_EOA_SIGNATURE: bool = false;
    const SIMULATION: bool = false;
}
```

`run_block` — the main sequencer entry point — hard-codes this config: [2](#0-1) 

```rust
run_forward::<BasicBootloaderForwardSimulationConfig>(
    oracle,
    &mut result_keeper,
    tracer,
    validator,
);
```

Both validation paths share the same guard. In the ZK flow: [3](#0-2) 

```rust
if let Some((parity, r, s)) = transaction.sig_parity_r_s() {
    if !Config::VALIDATE_EOA_SIGNATURE | Config::SIMULATION {
        // charge native but skip ecrecover entirely
        intrinsic_resources.charge(...)?;
    } else {
        // full ecrecover + from-address check
        ...
    }
}
```

For `BasicBootloaderForwardSimulationConfig`: `!false | false = true` → the `else` branch (actual signature check) is **never reached**. The sequencer charges native resources as if ecrecover ran, but never verifies the recovered address matches `from`.

The prover uses `BasicBootloaderProvingExecutionConfig`: [4](#0-3) 

```rust
impl BasicBootloaderExecutionConfig for BasicBootloaderProvingExecutionConfig {
    const SIMULATION: bool = false;
    const VALIDATE_EOA_SIGNATURE: bool = true;
}
```

For this config: `!true | false = false` → the full ecrecover path runs, and a mismatch between the recovered address and `from` returns `Err(InvalidTransaction::IncorrectFrom { ... })`.

The identical guard exists in the Ethereum-like flow: [5](#0-4) 

---

### Impact Explanation

An attacker submits a transaction whose `from` field is set to a victim address but whose signature is arbitrary (e.g., all-zeros or a signature from a different key). The sequencer's bootloader:

1. Parses the transaction, reads `from` as the victim address.
2. Skips ecrecover entirely (`VALIDATE_EOA_SIGNATURE: false`).
3. Executes the transaction — nonce increment, balance deduction, calldata execution — all attributed to the victim.

The prover then re-executes the same block with `VALIDATE_EOA_SIGNATURE: true`, recovers a different address from the signature, and returns `IncorrectFrom`. The block cannot be proven. The chain halts at that batch until the sequencer rolls back or the block is discarded. This is a **valid-execution unprovability / forward-proving divergence** impact, and the sequencer's state diverges from any provable state.

---

### Likelihood Explanation

Any user can broadcast a transaction to the sequencer's RPC. The ZKsync OS bootloader is the only layer in the codebase that performs signature validation for L2 transactions; no separate mempool-level check is visible in the repository. Because `run_block` unconditionally uses `BasicBootloaderForwardSimulationConfig`, the bootloader never rejects a transaction for a bad signature during sequencing. A single crafted transaction is sufficient to produce an unprovable block.

---

### Recommendation

Replace `BasicBootloaderForwardSimulationConfig` with `BasicBootloaderProvingExecutionConfig` (or a new config with `VALIDATE_EOA_SIGNATURE: true, SIMULATION: false`) in the production `run_block` path: [2](#0-1) 

The comment in the test rig acknowledges this directly: *"we use proving config here for benchmarking, although sequencer can have extra optimizations."* The "optimization" of skipping signature validation is only safe if an external layer (mempool) enforces it — which is not guaranteed and not visible in this codebase. Signature validation via ecrecover is cheap relative to the cost of an unprovable block.

---

### Proof of Concept

1. Construct a valid EIP-1559 transaction targeting a victim address as `from`, with `value = victim_balance`, `to = attacker`, and a garbage 65-byte signature (e.g., `[0u8; 65]`).
2. Submit it to the sequencer via `eth_sendRawTransaction`.
3. The sequencer calls `run_block` → `BasicBootloaderForwardSimulationConfig` → `VALIDATE_EOA_SIGNATURE: false` → ecrecover skipped → transaction executed, victim's balance transferred to attacker.
4. The prover re-executes with `BasicBootloaderProvingExecutionConfig` → ecrecover runs → recovered address ≠ victim → `InvalidTransaction::IncorrectFrom` → block cannot be proven → chain halts. [6](#0-5) [7](#0-6) [8](#0-7)

### Citations

**File:** basic_bootloader/src/bootloader/config.rs (L1-40)
```rust
pub trait BasicBootloaderExecutionConfig: 'static + Clone + Copy + core::fmt::Debug {
    /// Flag to disable EOA signature validation.
    /// It can be used to optimize forward run.
    const VALIDATE_EOA_SIGNATURE: bool;
    /// Simulation flag(used for `eth_call` and `estimate_gas`)
    const SIMULATION: bool;
}

#[derive(Clone, Copy, Debug)]
pub struct BasicBootloaderProvingExecutionConfig;

impl BasicBootloaderExecutionConfig for BasicBootloaderProvingExecutionConfig {
    const SIMULATION: bool = false;
    const VALIDATE_EOA_SIGNATURE: bool = true;
}

#[derive(Clone, Copy, Debug)]
pub struct BasicBootloaderForwardSimulationConfig;

impl BasicBootloaderExecutionConfig for BasicBootloaderForwardSimulationConfig {
    const VALIDATE_EOA_SIGNATURE: bool = false;
    const SIMULATION: bool = false;
}

#[derive(Clone, Copy, Debug)]
pub struct BasicBootloaderCallSimulationConfig;

impl BasicBootloaderExecutionConfig for BasicBootloaderCallSimulationConfig {
    // doesn't really matter, as `SIMULATION` disables signature validation anyway
    const VALIDATE_EOA_SIGNATURE: bool = true;
    const SIMULATION: bool = true;
}

#[derive(Clone, Copy, Debug)]
pub struct BasicBootloaderForwardETHLikeConfig;

impl BasicBootloaderExecutionConfig for BasicBootloaderForwardETHLikeConfig {
    const VALIDATE_EOA_SIGNATURE: bool = true;
    const SIMULATION: bool = false;
}
```

**File:** forward_system/src/run/mod.rs (L67-102)
```rust
pub fn run_block<T: ReadStorageTree, PS: PreimageSource, TS: TxSource, TR: TxResultCallback>(
    block_context: BlockContext,
    tree: T,
    preimage_source: PS,
    tx_source: TS,
    tx_result_callback: TR,
    tracer: &mut impl Tracer<ForwardRunningSystem>,
    validator: &mut impl TxValidator<ForwardRunningSystem>,
) -> Result<BlockOutput, ForwardSubsystemError> {
    let block_metadata_responder = BlockMetadataResponder {
        block_metadata: block_context,
    };
    let tx_data_responder = TxDataResponder {
        tx_source,
        next_tx: None,
        next_tx_format: None,
        next_tx_from: None,
    };
    let preimage_responder = GenericPreimageResponder { preimage_source };
    let tree_responder = ReadTreeResponder { tree };

    let mut oracle = ZkEENonDeterminismSource::default();
    oracle.add_external_processor(block_metadata_responder);
    oracle.add_external_processor(tx_data_responder);
    oracle.add_external_processor(preimage_responder);
    oracle.add_external_processor(tree_responder);

    let mut result_keeper = ForwardRunningResultKeeper::new(tx_result_callback);

    run_forward::<BasicBootloaderForwardSimulationConfig>(
        oracle,
        &mut result_keeper,
        tracer,
        validator,
    );
    Ok(result_keeper.into())
```

**File:** basic_bootloader/src/bootloader/transaction_flow/zk/validation_impl.rs (L249-299)
```rust
    if let Some((parity, r, s)) = transaction.sig_parity_r_s() {
        // Even if we don't validate a signature, we still need to charge for ecrecover for equivalent behavior
        // Note that gas is charged already in intrinsic cost, so now
        // we only need to charge native resources.
        if !Config::VALIDATE_EOA_SIGNATURE | Config::SIMULATION {
            intrinsic_resources.charge(&Resources::from_native(
                <<S as SystemTypes>::Resources as Resources>::Native::from_computational(
                    ECRECOVER_NATIVE_COST,
                ),
            ))?;
        } else {
            if U256::from_be_slice(s) > U256::from_be_bytes(SECP256K1N_HALF) {
                return Err(InvalidTransaction::MalleableSignature.into());
            }

            let mut ecrecover_input = [0u8; 128];
            ecrecover_input[0..32].copy_from_slice(suggested_signed_hash.as_u8_array_ref());
            ecrecover_input[63] = (parity as u8) + 27;
            ecrecover_input[64..96][(32 - r.len())..].copy_from_slice(r);
            ecrecover_input[96..128][(32 - s.len())..].copy_from_slice(s);

            let mut ecrecover_output = ArrayBuilder::default();
            // We already charged gas for ecrecover in intrinsic cost, so we only need to charge native resources here.
            intrinsic_resources.with_infinite_ergs(|resources| {
                S::SystemFunctions::secp256k1_ec_recover(
                    ecrecover_input.as_slice(),
                    &mut ecrecover_output,
                    resources,
                    system.get_allocator(),
                )
                .map_err(SystemError::from)
            })?;

            if ecrecover_output.is_empty() {
                return Err(InvalidTransaction::IncorrectFrom {
                    recovered: B160::ZERO,
                    tx: from,
                }
                .into());
            }

            let recovered_from = B160::try_from_be_slice(&ecrecover_output.build()[12..])
                .ok_or(internal_error!("Invalid ecrecover return value"))?;

            if recovered_from != from {
                return Err(InvalidTransaction::IncorrectFrom {
                    recovered: recovered_from,
                    tx: from,
                }
                .into());
            }
```

**File:** basic_bootloader/src/bootloader/transaction_flow/ethereum/validation_impl.rs (L201-201)
```rust
    if !Config::VALIDATE_EOA_SIGNATURE | Config::SIMULATION {
```
