### Title
Forward/Proving Divergence via Unconditional EOA Signature Bypass in Production `run_block` - (File: `forward_system/src/run/mod.rs`)

### Summary
The production `run_block` entry point hardcodes `BasicBootloaderForwardSimulationConfig`, which sets `VALIDATE_EOA_SIGNATURE: false`. This completely skips cryptographic signature verification during forward (sequencer) execution. The prover uses `BasicBootloaderProvingExecutionConfig` with `VALIDATE_EOA_SIGNATURE: true`. Any transaction with an invalid or forged signature accepted by the forward run will be rejected by the prover, creating a forward/proving divergence that forces block re-execution and enables a sustained DoS against the sequencer.

### Finding Description

**Root cause — config mismatch between forward and proving runs:**

`forward_system/src/run/mod.rs` line 96 hardcodes the forward config:

```rust
run_forward::<BasicBootloaderForwardSimulationConfig>(oracle, &mut result_keeper, tracer, validator);
```

`basic_bootloader/src/bootloader/config.rs` lines 20–23 define that config:

```rust
impl BasicBootloaderExecutionConfig for BasicBootloaderForwardSimulationConfig {
    const VALIDATE_EOA_SIGNATURE: bool = false;   // ← signature check OFF
    const SIMULATION: bool = false;
}
```

The proving config (lines 12–15) does the opposite:

```rust
impl BasicBootloaderExecutionConfig for BasicBootloaderProvingExecutionConfig {
    const VALIDATE_EOA_SIGNATURE: bool = true;    // ← signature check ON
    const SIMULATION: bool = false;
}
```

**Where the bypass fires in validation:**

`basic_bootloader/src/bootloader/transaction_flow/zk/validation_impl.rs` lines 249–300:

```rust
if let Some((parity, r, s)) = transaction.sig_parity_r_s() {
    if !Config::VALIDATE_EOA_SIGNATURE | Config::SIMULATION {
        // charge native cost only — NO ecrecover, NO address comparison
        intrinsic_resources.charge(...)?;
    } else {
        // ecrecover + recovered_from != from check
    }
}
```

With `VALIDATE_EOA_SIGNATURE = false` and `SIMULATION = false`, the condition `!false | false = true` is always satisfied, so the entire ecrecover block is skipped. The `from` address is consumed as an unverified hint from the transaction data.

The identical bypass exists in the Ethereum-path validator at `basic_bootloader/src/bootloader/transaction_flow/ethereum/validation_impl.rs` lines 201–246.

**Attacker-controlled entry path:**

1. Attacker submits a transaction to the sequencer mempool with an invalid signature (or, for ABI-encoded ZK transactions, a forged `from` address pointing to a funded account).
2. The sequencer calls `run_block` → `run_forward::<BasicBootloaderForwardSimulationConfig>`.
3. Forward validation at line 253 skips ecrecover; the transaction is accepted and executed.
4. Nonce is incremented, fees are deducted, and contract calls execute — all against the forged `from`.
5. The prover runs `BasicBootloaderProvingExecutionConfig`, calls ecrecover, and the recovered address does not match `from`. The block is unprovable.
6. The sequencer must detect the divergence and re-execute the block without the offending transaction.
7. Attacker repeats, continuously invalidating blocks.

The same `BasicBootloaderForwardSimulationConfig` is also used in `run_block_with_oracle_dump` (line 337) and `run_block_from_oracle_dump` (line 460), widening the surface.

### Impact Explanation

- **Forward/proving divergence**: every block containing a signature-invalid transaction is unprovable. The sequencer's committed local state diverges from what can be proven and submitted to L1.
- **DoS against the sequencer**: the attacker can continuously inject invalid transactions, forcing repeated block re-execution and preventing timely L1 finality.
- **Temporary unauthorized state mutation**: during the forward run, nonce increments and balance deductions execute against the forged `from` address before the divergence is detected. Subsequent transactions in the same block may observe this corrupted intermediate state.
- **No permanent fund loss** (prover rejects the block before L1 commitment), but liveness and state integrity of the sequencer are broken.

### Likelihood Explanation

- Submitting a transaction to the sequencer mempool requires no privilege — it is the standard unprivileged user action.
- The sequencer's `run_block` API provides no internal signature gate; the `TxValidator` hook is optional and defaults to `NopTxValidator` in all observed call sites.
- Crafting a transaction with an invalid signature is trivial (random bytes for `r`, `s`, `v`).
- The attack is repeatable at negligible cost.

### Recommendation

1. Replace `BasicBootloaderForwardSimulationConfig` in `run_block` with `BasicBootloaderProvingExecutionConfig` (or `BasicBootloaderForwardETHLikeConfig`), both of which set `VALIDATE_EOA_SIGNATURE: true`, so the forward run rejects invalid signatures before they can cause divergence.
2. If the performance optimization of skipping ecrecover in the forward run is intentional, enforce signature pre-validation in the `TxValidator` parameter and document it as a mandatory caller contract.
3. Add a divergence-detection assertion in the testing rig that runs both configs on the same transaction set and asserts identical accept/reject outcomes.

### Proof of Concept

```
1. Craft an EIP-1559 transaction:
   - from:  0xWhale  (any funded address)
   - r, s:  random 32-byte values (invalid signature)
   - v:     27

2. Submit to sequencer mempool.

3. Sequencer calls forward_system::run::run_block(...)
   → run_forward::<BasicBootloaderForwardSimulationConfig>(...)
   → validate_and_compute_fee_for_transaction::<..., BasicBootloaderForwardSimulationConfig>(...)
   → line 253: `!false | false == true` → ecrecover skipped
   → transaction accepted, 0xWhale nonce incremented, fee deducted

4. Prover calls run_proving(...)
   → validate_and_compute_fee_for_transaction::<..., BasicBootloaderProvingExecutionConfig>(...)
   → line 253: `!true | false == false` → ecrecover executed
   → recovered address ≠ 0xWhale → InvalidTransaction::IncorrectFrom
   → block unprovable

5. Sequencer detects divergence, must re-execute block — DoS achieved.
   Repeat from step 1 to sustain the attack.
``` [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5) [7](#0-6)

### Citations

**File:** forward_system/src/run/mod.rs (L94-102)
```rust
    let mut result_keeper = ForwardRunningResultKeeper::new(tx_result_callback);

    run_forward::<BasicBootloaderForwardSimulationConfig>(
        oracle,
        &mut result_keeper,
        tracer,
        validator,
    );
    Ok(result_keeper.into())
```

**File:** forward_system/src/run/mod.rs (L335-348)
```rust
    validator: &mut impl TxValidator<ForwardRunningSystem>,
) -> Result<BlockOutput, ForwardSubsystemError> {
    run_block_with_oracle_dump_ext::<T, PS, TS, TR, BasicBootloaderForwardSimulationConfig>(
        block_context,
        tree,
        preimage_source,
        tx_source,
        tx_result_callback,
        proof_data,
        da_commitment_scheme,
        tracer,
        validator,
    )
}
```

**File:** forward_system/src/run/mod.rs (L458-466)
```rust
    let mut result_keeper = ForwardRunningResultKeeper::new(NoopTxCallback);

    run_forward::<BasicBootloaderForwardSimulationConfig>(
        oracle,
        &mut result_keeper,
        tracer,
        validator,
    );
    Ok(result_keeper.into())
```

**File:** basic_bootloader/src/bootloader/config.rs (L9-15)
```rust
#[derive(Clone, Copy, Debug)]
pub struct BasicBootloaderProvingExecutionConfig;

impl BasicBootloaderExecutionConfig for BasicBootloaderProvingExecutionConfig {
    const SIMULATION: bool = false;
    const VALIDATE_EOA_SIGNATURE: bool = true;
}
```

**File:** basic_bootloader/src/bootloader/config.rs (L17-23)
```rust
#[derive(Clone, Copy, Debug)]
pub struct BasicBootloaderForwardSimulationConfig;

impl BasicBootloaderExecutionConfig for BasicBootloaderForwardSimulationConfig {
    const VALIDATE_EOA_SIGNATURE: bool = false;
    const SIMULATION: bool = false;
}
```

**File:** basic_bootloader/src/bootloader/transaction_flow/zk/validation_impl.rs (L249-301)
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
        }
    };
```

**File:** basic_bootloader/src/bootloader/transaction_flow/ethereum/validation_impl.rs (L201-246)
```rust
    if !Config::VALIDATE_EOA_SIGNATURE | Config::SIMULATION {
        // No native for Eth STF
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
        tx_resources
            .main_resources
            .with_infinite_ergs(|resources| {
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
    }
```
