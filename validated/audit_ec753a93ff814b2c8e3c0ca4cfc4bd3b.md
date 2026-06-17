### Title
Forward/Proving Divergence via Unconditionally Skipped EOA Signature Validation in Sequencer Forward Run — (File: `basic_bootloader/src/bootloader/config.rs`)

### Summary
`BasicBootloaderForwardSimulationConfig`, the config used by the production sequencer `run_block` path, sets `VALIDATE_EOA_SIGNATURE: false`. The proving run uses `BasicBootloaderProvingExecutionConfig` with `VALIDATE_EOA_SIGNATURE: true`. This structural mismatch means the sequencer accepts transactions with invalid or forged signatures that the prover will unconditionally reject, creating a forward/proving divergence exploitable by any unprivileged transaction sender.

### Finding Description

In `basic_bootloader/src/bootloader/config.rs`, two configs exist side-by-side:

```rust
// Sequencer forward run — used by run_block()
impl BasicBootloaderExecutionConfig for BasicBootloaderForwardSimulationConfig {
    const VALIDATE_EOA_SIGNATURE: bool = false;   // ← skips all signature checks
    const SIMULATION: bool = false;
}

// Proving run
impl BasicBootloaderExecutionConfig for BasicBootloaderProvingExecutionConfig {
    const VALIDATE_EOA_SIGNATURE: bool = true;    // ← enforces signature checks
    const SIMULATION: bool = false;
}
``` [1](#0-0) 

The production sequencer entry point `run_block` in `forward_system/src/run/mod.rs` instantiates the forward run with `BasicBootloaderForwardSimulationConfig`:

```rust
run_forward::<BasicBootloaderForwardSimulationConfig>(oracle, &mut result_keeper, tracer, validator);
``` [2](#0-1) 

Inside both `ethereum/validation_impl.rs` and `zk/validation_impl.rs`, the entire signature verification block is gated on this flag:

```rust
if !Config::VALIDATE_EOA_SIGNATURE | Config::SIMULATION {
    // No native for Eth STF — signature check entirely omitted
} else {
    // ecrecover, malleable-S check, recovered-address comparison
}
``` [3](#0-2) [4](#0-3) 

Critically, `from` is read **before** the skipped check:

```rust
let from = *transaction.from();   // taken verbatim, never verified
``` [5](#0-4) 

For ZKsync-native transactions the `from` field is explicit in the wire format. An attacker sets it to any victim address. Nonce and balance checks still run against that address, so the sequencer will accept the transaction if the victim's nonce and balance match — but the prover, running `BasicBootloaderProvingExecutionConfig`, will recompute `ecrecover` and reject the block because the recovered address does not match `from`.

The same `BasicBootloaderForwardSimulationConfig` is also used in `run_block_with_oracle_dump` and `run_block_from_oracle_dump`: [6](#0-5) [7](#0-6) 

### Impact Explanation

**Vulnerability class**: Forward/proving divergence + authentication bypass.

1. **Sequencer state corruption**: The sequencer executes the forged transaction, debiting the victim's balance and crediting the attacker's address in its local state.
2. **Unprovable block**: The prover rejects the block because `ecrecover(forged_sig) ≠ from`. The block cannot be finalized on L1.
3. **Sequencer halt / forced rollback**: If the sequencer has no automatic recovery path for unprovable blocks, it stalls. Even with recovery, every such submission forces an expensive rollback cycle.
4. **Temporary fund freeze**: Victim's balance appears spent in the sequencer's view until the rollback completes, potentially blocking dependent transactions.

Direct L1 fund theft is prevented by the prover's rejection, but sequencer liveness and temporary state integrity are concretely harmed.

### Likelihood Explanation

- **Attacker prerequisites**: None beyond the ability to submit a transaction to the sequencer (standard user capability).
- **Information needed**: Victim's address and current nonce — both publicly observable on-chain.
- **Effort**: Trivial. Craft a ZKsync-native transaction with `from = victim`, `nonce = victim_nonce`, arbitrary invalid signature, submit via the public RPC.
- **Repeatability**: The attack can be repeated continuously, keeping the sequencer in a rollback loop.

### Recommendation

- **Short term**: Set `VALIDATE_EOA_SIGNATURE: true` in `BasicBootloaderForwardSimulationConfig`, or add a lightweight pre-filter in `run_block` that rejects transactions whose recovered signer does not match the declared `from` before handing them to the bootloader. The proving config already demonstrates the correct pattern.
- **Long term**: Enforce a strict invariant that any config used in a state-mutating forward run must have `VALIDATE_EOA_SIGNATURE: true`. Consider a compile-time assertion or type-level enforcement so that `VALIDATE_EOA_SIGNATURE: false` is only permitted when `SIMULATION: true`.

### Proof of Concept

1. Observe victim address `V` with nonce `N` and balance `B > gas_cost`.
2. Construct a ZKsync-native transaction: `from = V`, `nonce = N`, `to = attacker`, `value = B - gas_cost`, signature = 65 zero bytes.
3. Submit to the sequencer's public RPC endpoint.
4. The sequencer calls `run_block → run_forward::<BasicBootloaderForwardSimulationConfig>`.
5. `validation_impl.rs` line 201: `!false | false = true` → signature block is skipped entirely.
6. Nonce check passes (`N == N`), balance check passes (`B ≥ cost`). Transaction is executed; sequencer state shows `V`'s balance zeroed.
7. Prover runs `BasicBootloaderProvingExecutionConfig` (`VALIDATE_EOA_SIGNATURE: true`), calls `ecrecover(zero_sig)` → recovered address ≠ `V` → block rejected.
8. Sequencer cannot finalize the block; liveness is disrupted. Repeat from step 2 to maintain the denial-of-service.

### Citations

**File:** basic_bootloader/src/bootloader/config.rs (L18-23)
```rust
pub struct BasicBootloaderForwardSimulationConfig;

impl BasicBootloaderExecutionConfig for BasicBootloaderForwardSimulationConfig {
    const VALIDATE_EOA_SIGNATURE: bool = false;
    const SIMULATION: bool = false;
}
```

**File:** forward_system/src/run/mod.rs (L96-101)
```rust
    run_forward::<BasicBootloaderForwardSimulationConfig>(
        oracle,
        &mut result_keeper,
        tracer,
        validator,
    );
```

**File:** forward_system/src/run/mod.rs (L337-348)
```rust
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

**File:** forward_system/src/run/mod.rs (L460-466)
```rust
    run_forward::<BasicBootloaderForwardSimulationConfig>(
        oracle,
        &mut result_keeper,
        tracer,
        validator,
    );
    Ok(result_keeper.into())
```

**File:** basic_bootloader/src/bootloader/transaction_flow/ethereum/validation_impl.rs (L195-246)
```rust
    let from = *transaction.from();
    let Some((parity, r, s)) = transaction.sig_parity_r_s() else {
        // Ethereum txs should have signature
        return Err(InvalidTransaction::InvalidStructure.into());
    };

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

**File:** basic_bootloader/src/bootloader/transaction_flow/zk/validation_impl.rs (L253-300)
```rust
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
```
