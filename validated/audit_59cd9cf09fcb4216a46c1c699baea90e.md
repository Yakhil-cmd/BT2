### Title
Unauthorized Interop Root Injection via Unguarded Event Hook — (`system_hooks/src/event_hooks/interop_root_reporter.rs`)

### Summary
`interop_root_reporter_event_hook` adds interop roots to the system's `InteropRootStorage` whenever it observes an `InteropRootAdded` event. The hook validates only the event signature and data format — it never checks which contract address emitted the event. Any unprivileged EVM contract that emits a correctly-formatted `InteropRootAdded(uint256,uint256,bytes32[])` log can inject arbitrary interop roots into the system state, corrupting the `interop_roots_rolling_hash` committed in the batch public input.

### Finding Description

`interop_root_reporter_event_hook` is the system-level event hook responsible for recording cross-chain interop roots into the ZKsync OS IO subsystem. Its full signature is:

```rust
pub fn interop_root_reporter_event_hook<S: EthereumLikeTypes>(
    topics: &arrayvec::ArrayVec<...>,
    data: &[u8],
    _caller_ee: u8,
    system: &mut System<S>,
    resources: &mut S::Resources,
) -> Result<(), SystemError>
``` [1](#0-0) 

The function receives no emitter address parameter. The `_caller_ee` field is the execution environment type (EVM/EraVM), not the emitting contract's address, and it is explicitly unused (prefixed `_`).

The hook's only guards are:

1. Event signature matches `INTEROP_ROOT_ADDED_EVENT_SIG`
2. `data.len() == 96`
3. ABI offset word equals `32`
4. Array length word equals `1`
5. `topics.len() == 3` [2](#0-1) 

After passing these checks the hook unconditionally calls:

```rust
system.io.add_interop_root(
    ExecutionEnvironmentType::NoEE,
    resources,
    InteropRoot { root, block_or_batch_number, chain_id },
)?;
``` [3](#0-2) 

`add_interop_root` pushes the root into `InteropRootStorage` without any further authorization check:

```rust
pub fn push_root(&mut self, interop_root: InteropRoot) -> Result<(), SystemError> {
    self.list.push(interop_root, ());
    Ok(())
}
``` [4](#0-3) 

Contrast this with every call-based system hook, which explicitly checks the caller address before performing any privileged action. For example, `mint_base_token_hook` immediately returns an empty response for any caller that is not `L2_BASE_TOKEN_ADDRESS`:

```rust
if caller != L2_BASE_TOKEN_ADDRESS {
    return Ok((make_return_state_from_returndata_region(available_resources, &[]), return_memory));
}
``` [5](#0-4) 

The intended flow requires a service transaction targeting `L2_INTEROP_ROOT_STORAGE_ADDRESS` with selector `addInteropRootsInBatch` (whitelisted in `SERVICE_DESTINATION_WHITELIST`): [6](#0-5) 

That contract emits `InteropRootAdded`, which the hook intercepts. Because the hook does not verify the emitter, any regular EVM contract can replicate the emission and bypass the service-transaction whitelist entirely.

### Impact Explanation

The injected roots are accumulated into `interop_roots_rolling_hash`, which is committed as part of `BatchOutput` and ultimately hashed into `BatchPublicInput`: [7](#0-6) 

An attacker who injects fake interop roots can:

- **Forge cross-chain message proofs**: downstream L1/L2 contracts that verify interop roots against the committed rolling hash will accept fraudulent cross-chain messages as proven.
- **Corrupt the batch commitment**: the prover will compute a different `interop_roots_rolling_hash` than the sequencer, causing a forward/proving divergence that either breaks batch finalization or forces the sequencer to include the attacker's roots in the proven output.

This is a direct, unprivileged path to cross-chain state corruption and potential fund theft via fraudulent interop message acceptance.

### Likelihood Explanation

The attack requires only a deployed EVM contract that emits a correctly ABI-encoded `InteropRootAdded` log. No special privileges, leaked keys, or governance access are needed. The attacker controls `chain_id`, `block_or_batch_number`, and `root` entirely. The attack is repeatable across any block.

### Recommendation

Add an emitter-address parameter to `interop_root_reporter_event_hook` (or pass it through the event hook dispatch infrastructure) and reject events not originating from `L2_INTEROP_ROOT_STORAGE_ADDRESS`:

```rust
if emitter != L2_INTEROP_ROOT_STORAGE_ADDRESS {
    return Ok(());
}
```

This mirrors the pattern already used by all call-based system hooks.

### Proof of Concept

1. Deploy an EVM contract with the following logic (pseudocode):
   ```solidity
   function attack() external {
       emit InteropRootAdded(
           attacker_chain_id,
           attacker_block_number,
           [attacker_root]
       );
   }
   ```
   where the event signature matches `keccak256("InteropRootAdded(uint256,uint256,bytes32[])")` = `0x6b451b84...`.

2. Submit a regular EIP-1559 transaction calling `attack()`.

3. The EVM interpreter emits the log; the event hook dispatch fires `interop_root_reporter_event_hook`.

4. The hook passes all format checks (correct signature, `data.len()==96`, offset==32, len==1, 3 topics) and calls `system.io.add_interop_root(...)` with the attacker-supplied values.

5. The attacker-controlled root is now part of `interop_roots_rolling_hash` in the batch public input, indistinguishable from a legitimately imported interop root.

### Citations

**File:** system_hooks/src/event_hooks/interop_root_reporter.rs (L19-66)
```rust
pub fn interop_root_reporter_event_hook<S: EthereumLikeTypes>(
    topics: &arrayvec::ArrayVec<<S::IOTypes as SystemIOTypesConfig>::EventKey, MAX_EVENT_TOPICS>,
    data: &[u8],
    _caller_ee: u8,
    system: &mut System<S>,
    resources: &mut S::Resources,
) -> Result<(), SystemError>
where
{
    // First, ensure we're capturing the InteropRootAdded event
    if topics.is_empty() || topics[0].as_u8_array() != INTEROP_ROOT_ADDED_EVENT_SIG {
        return Ok(());
    }
    // Internal error if the data supplied doesn't match the expected value
    if data.len() != 96 {
        return Err(internal_error!("Interop root reporter event hook received bad data").into());
    }

    // Parse data
    let offset: u32 = match U256::from_be_slice(&data[..32]).try_into() {
        Ok(offset) => offset,
        Err(_) => {
            return Err(
                internal_error!("Interop root reporter event hook received bad offset").into(),
            );
        }
    };
    // This event is part of the system, but we check it anyways
    if offset != 32 {
        return Err(internal_error!("Interop root reporter event hook received bad offset").into());
    }

    let len: u32 = match U256::from_be_slice(&data[32..64]).try_into() {
        Ok(offset) => offset,
        Err(_) => {
            return Err(
                internal_error!("Interop root reporter event hook received bad length").into(),
            );
        }
    };
    // It should have exactly one side
    if len != 1 {
        return Err(internal_error!("Interop root reporter event hook received bad length").into());
    }
    // Validate topics length
    if topics.len() != 3 {
        return Err(internal_error!("Interop root reporter event hook received bad topics").into());
    }
```

**File:** system_hooks/src/event_hooks/interop_root_reporter.rs (L71-79)
```rust
    system.io.add_interop_root(
        ExecutionEnvironmentType::NoEE,
        resources,
        InteropRoot {
            root,
            block_or_batch_number,
            chain_id,
        },
    )?;
```

**File:** zk_ee/src/common_structs/interop_root_storage.rs (L41-45)
```rust
    pub fn push_root(&mut self, interop_root: InteropRoot) -> Result<(), SystemError> {
        self.list.push(interop_root, ());

        Ok(())
    }
```

**File:** system_hooks/src/call_hooks/mint_base_token.rs (L39-46)
```rust
    // Only allow L2 base token contract to mint tokens
    if caller != L2_BASE_TOKEN_ADDRESS {
        // Pretend to be an empty account
        return Ok((
            make_return_state_from_returndata_region(available_resources, &[]),
            return_memory,
        ));
    }
```

**File:** basic_bootloader/src/bootloader/transaction/rlp_encoded/transaction_types/service_tx.rs (L40-47)
```rust
const SERVICE_DESTINATION_WHITELIST: &[(B160, [u8; 4])] = &[
    (
        L2_INTEROP_ROOT_STORAGE_ADDRESS,
        ADD_INTEROP_ROOTS_IN_BATCH_SELECTOR,
    ),
    (SYSTEM_CONTEXT_ADDRESS, SET_SL_CHAIN_ID_SELECTOR),
    (L2_INTEROP_CENTER_ADDRESS, SET_INTEROP_FEE_SELECTOR),
];
```

**File:** basic_bootloader/src/bootloader/block_flow/zk/post_tx_op/post_tx_op_proving_singleblock_batch.rs (L185-205)
```rust
        let batch_output = BatchOutput {
            chain_id: U256::from(metadata.chain_id()),
            first_block_timestamp: metadata.block_timestamp(),
            last_block_timestamp: metadata.block_timestamp(),
            da_commitment_scheme: io.da_commitment_scheme.unwrap(),
            pubdata_commitment: da_commitment,
            number_of_layer_1_txs: U256::try_from(number_of_layer_1_txs).unwrap(),
            number_of_layer_2_txs: U256::from(number_of_layer_2_txs),
            priority_operations_hash,
            l2_logs_tree_root: full_l2_to_l1_logs_root,
            upgrade_tx_hash,
            interop_roots_rolling_hash,
            settlement_layer_chain_id,
        };
        logger_log!(logger, "PI calculation: batch output {:?}\n", batch_output,);

        let public_input = BatchPublicInput {
            state_before: chain_state_commitment_before.hash().into(),
            state_after: chain_state_commitment_after.hash().into(),
            batch_output: batch_output.hash().into(),
        };
```
