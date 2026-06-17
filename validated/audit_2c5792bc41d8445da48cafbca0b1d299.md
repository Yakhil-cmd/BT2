### Title
`SystemEventHook` Callback Missing Emitting Contract Address Parameter — (`zk_ee/src/common_structs/system_hooks.rs`)

---

### Summary

The `SystemEventHook` function type does not receive the address of the contract that emitted the event. In `try_intercept_event`, the `address_low` key is used only to look up the registered hook but is never forwarded to the hook callback itself. This is a direct structural analog to the Holograph finding: a hook/callback is invoked with incomplete context, preventing it from verifying or reacting to the identity of the initiating party.

---

### Finding Description

In `zk_ee/src/common_structs/system_hooks.rs`, the `SystemEventHook` type is defined as a function pointer with the following signature:

```rust
pub struct SystemEventHook<S: SystemTypes>(
    for<'a> fn(
        &arrayvec::ArrayVec<...EventKey, MAX_EVENT_TOPICS>,  // topics
        &[u8],                                                // data
        u8,                                                   // caller_ee
        &mut System<S>,
        &mut S::Resources,
    ) -> Result<(), SystemError>,
);
``` [1](#0-0) 

The emitting contract's address is entirely absent from the hook's parameter list. In `try_intercept_event`, `address_low` is used only as a map key to retrieve the hook, but is **not** passed to `hook.0(...)`:

```rust
pub fn try_intercept_event(
    &mut self,
    address_low: u32,   // ← used for lookup only, never forwarded
    topics: ...,
    data: &[u8],
    caller_ee: u8,
    system: &mut System<S>,
    resources: &mut S::Resources,
) -> Result<Option<()>, SystemError> {
    let Some(hook) = self.event_hooks.get(&address_low) else {
        return Ok(None);
    };
    hook.0(topics, data, caller_ee, system, resources)?;  // address_low dropped here
    Ok(Some(()))
}
``` [2](#0-1) 

The call site in `System::emit_event` extracts `address_low` from the full emitting address and passes it to `try_intercept_event`, but the full address is never made available to the hook: [3](#0-2) 

The event hooks registered in `system_hooks/src/event_hooks/` (for `SYSTEM_CONTEXT_ADDRESS` and `L2_INTEROP_ROOT_STORAGE_ADDRESS`) therefore have no way to verify which contract actually emitted the event they are processing.



---

### Impact Explanation

System event hooks are designed to process events exclusively from specific trusted system contracts. Because the hook callback never receives the emitting address, it cannot perform any source-address verification internally. If an attacker deploys a contract whose address shares the same low 32 bits as a registered system contract address (e.g., `SYSTEM_CONTEXT_ADDRESS`), that contract can emit events that trigger the system event hook with fully attacker-controlled `topics` and `data`. The hook will process this attacker-supplied data as if it originated from the legitimate system contract, potentially causing incorrect state transitions or corrupted L1 messages depending on what the hook does with the data.

---

### Likelihood Explanation

The `address_low` key is a `u32` (32 bits). An attacker using CREATE2 can grind a salt to produce a deployment address whose low 32 bits match a target system contract address in approximately 2^32 hash operations — well within reach of modern hardware. The attacker-controlled entry path is: deploy a contract via CREATE2 with a matching address → call a function that emits a LOG opcode with crafted topics/data → `System::emit_event` triggers `try_intercept_event` → the system event hook executes with attacker-supplied inputs. [4](#0-3) 

---

### Recommendation

Add the emitting contract's address (at minimum `address_low: u32`, ideally the full address type) as an explicit parameter to the `SystemEventHook` function type and forward it through `try_intercept_event`:

```rust
// Before
pub struct SystemEventHook<S: SystemTypes>(
    for<'a> fn(
        &arrayvec::ArrayVec<...>,
        &[u8],
        u8,
        &mut System<S>,
        &mut S::Resources,
    ) -> Result<(), SystemError>,
);

// After
pub struct SystemEventHook<S: SystemTypes>(
    for<'a> fn(
        u32,                        // address_low of emitting contract
        &arrayvec::ArrayVec<...>,
        &[u8],
        u8,
        &mut System<S>,
        &mut S::Resources,
    ) -> Result<(), SystemError>,
);
```

Each registered hook implementation should then assert that the received `address_low` matches the address it was registered for, rejecting any invocation from an unexpected source. [5](#0-4) 

---

### Proof of Concept

1. Identify a registered event hook address, e.g. `SYSTEM_CONTEXT_ADDRESS` (low 32-bit value `X`).
2. Use CREATE2 to deploy a contract at an address whose low 32 bits equal `X`. This requires ~2^32 hash operations.
3. From the deployed contract, execute a `LOG` opcode emitting attacker-chosen `topics` and `data`.
4. `EvmInterpreter::log` calls `System::emit_event` with the attacker's contract address.
5. `emit_event` calls `address.try_into_low()` → returns `Some(X)` → calls `try_intercept_event(X, topics, data, ...)`.
6. The system event hook registered for `X` fires with attacker-controlled inputs.
7. The hook has no way to distinguish this from a legitimate `SYSTEM_CONTEXT_ADDRESS` event and processes the attacker's data. [6](#0-5) [7](#0-6)

### Citations

**File:** zk_ee/src/common_structs/system_hooks.rs (L52-60)
```rust
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

**File:** zk_ee/src/common_structs/system_hooks.rs (L62-74)
```rust
impl<S: SystemTypes> SystemEventHook<S> {
    pub fn new(
        f: for<'a> fn(
            &arrayvec::ArrayVec<<S::IOTypes as SystemIOTypesConfig>::EventKey, MAX_EVENT_TOPICS>,
            &[u8],
            u8,
            &mut System<S>,
            &mut S::Resources,
        ) -> Result<(), SystemError>,
    ) -> Self {
        Self(f)
    }
}
```

**File:** zk_ee/src/common_structs/system_hooks.rs (L149-170)
```rust
    /// Intercepts events emitted from low addresses (< 2^32) and executes hooks
    /// stored under that address. If no hook is stored there, return `Ok(None)`.
    ///
    pub fn try_intercept_event(
        &mut self,
        address_low: u32,
        topics: &arrayvec::ArrayVec<
            <S::IOTypes as SystemIOTypesConfig>::EventKey,
            MAX_EVENT_TOPICS,
        >,
        data: &[u8],
        caller_ee: u8,
        system: &mut System<S>,
        resources: &mut S::Resources,
    ) -> Result<Option<()>, SystemError> {
        let Some(hook) = self.event_hooks.get(&address_low) else {
            return Ok(None);
        };
        hook.0(topics, data, caller_ee, system, resources)?;

        Ok(Some(()))
    }
```

**File:** zk_ee/src/system/mod.rs (L191-217)
```rust
    /// Emit an event, potentially capturing some using an event hook.
    pub fn emit_event(
        &mut self,
        hooks: &mut HooksStorage<S, S::Allocator>,
        ee_type: ExecutionEnvironmentType,
        resources: &mut S::Resources,
        address: &<S::IOTypes as SystemIOTypesConfig>::Address,
        topics: &ArrayVec<<S::IOTypes as SystemIOTypesConfig>::EventKey, MAX_EVENT_TOPICS>,
        data: &[u8],
    ) -> Result<(), SystemError> {
        // First, emit the event using io subsystem
        self.io
            .emit_event(ee_type, resources, address, topics, data)?;

        // If successful, intercept event hook, if any
        if let Some(address_low) = address.try_into_low() {
            let _ = hooks.try_intercept_event(
                address_low,
                topics,
                data,
                ee_type as u8,
                self,
                resources,
            )?;
        }
        Ok(())
    }
```

**File:** evm_interpreter/src/instructions/host.rs (L215-251)
```rust
    pub fn log<const N: usize>(
        &mut self,
        system: &mut System<S>,
        hooks: &mut HooksStorage<S, S::Allocator>,
        tracer: &mut impl Tracer<S>,
    ) -> InstructionResult {
        assert!(N <= MAX_EVENT_TOPICS);
        self.gas.spend_gas_and_native(0, LOG_NATIVE_COST)?;

        if self.is_static_frame() {
            return Err(EvmError::StateChangeDuringStaticCall.into());
        }

        let (mem_offset, len) = self.stack.pop_2()?;
        let (mem_offset, len) =
            Self::cast_offset_and_len(&mem_offset, &len, EvmError::InvalidOperandOOG.into())?;
        let mut topics: arrayvec::ArrayVec<Bytes32, 4> = arrayvec::ArrayVec::new();
        for _ in 0..N {
            topics.push(Bytes32::from_u256_be(self.stack.pop_1()?));
        }

        // resize memory
        self.resize_heap(mem_offset, len)?;
        let data = &self.heap[mem_offset..mem_offset + len];

        tracer.on_event(THIS_EE_TYPE, &self.address, &topics, data);

        system.emit_event(
            hooks,
            ExecutionEnvironmentType::EVM,
            self.gas.resources_mut(),
            &self.address,
            &topics,
            data,
        )?;

        Ok(())
```
