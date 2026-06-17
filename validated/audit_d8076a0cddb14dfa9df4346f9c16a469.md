### Title
Missing EVM Event Emission on L2→L1 Message Send — (`basic_system/src/system_implementation/system/io_subsystem.rs`)

---

### Summary

`emit_l1_message` in `FullIO` records an L2→L1 message in `logs_storage` but never calls `emit_event`. The codebase itself acknowledges this gap with a TODO comment. Any unprivileged user who calls the L1 messenger system contract will have their message silently stored without a corresponding EVM log being emitted, making the action invisible to all off-chain indexers, bridge relayers, and monitoring systems that watch for EVM events.

---

### Finding Description

In `basic_system/src/system_implementation/system/io_subsystem.rs`, the `emit_l1_message` implementation pushes the message to `logs_storage` and returns the data hash, but never calls `self.emit_event(...)`: [1](#0-0) 

The explicit developer acknowledgment of the gap is at line 216: [2](#0-1) 

```
// TODO(EVM-1078): for Era backward compatibility we may need to add events for l2 to l1 log and l1 message
```

In ZKsync Era, `L1Messenger.sendToL1()` emits **both** an L2→L1 log (the cross-chain payload) **and** an EVM event (for off-chain consumers). ZKsync OS only produces the former.

The user-reachable entry path is:

1. Any EOA or contract calls the L1 messenger system contract at `L1_MESSENGER_ADDRESS`.
2. The call is intercepted by `l1_messenger_hook` in `system_hooks/src/call_hooks/l1_messenger.rs`. [3](#0-2) 

3. After access-control checks, `send_to_l1_inner` is called, which calls `system.io.emit_l1_message(...)`. [4](#0-3) 

4. `emit_l1_message` stores the message but emits no EVM event.

The hook is registered unconditionally for all transactions: [5](#0-4) 

---

### Impact Explanation

Bridge relayers, withdrawal processors, and monitoring systems that watch for EVM `L1MessageSent` (or equivalent) events to detect and relay L2→L1 messages will receive **no signal**. A user who calls `sendToL1` to initiate a withdrawal will have their message committed to the batch's `logs_storage` (so the ZK proof is correct), but no EVM event is emitted. Any off-chain component that relies on event-driven detection — which is the standard pattern for ZKsync Era bridges — will silently miss the message, potentially leaving withdrawals permanently unprocessed.

---

### Likelihood Explanation

Every call to the L1 messenger system contract by any unprivileged user triggers this path. No special permissions, governance access, or privileged keys are required. The missing event affects every L2→L1 message sent through the system.

---

### Recommendation

In `emit_l1_message`, after pushing to `logs_storage`, call `self.emit_event(...)` with the appropriate topic (e.g., `L1MessageSent(address indexed _sender, bytes32 indexed _hash, bytes _message)`) to match ZKsync Era semantics and ensure off-chain consumers receive the expected signal. The TODO at line 216 (`EVM-1078`) should be resolved before production deployment.

---

### Proof of Concept

1. Deploy a contract on ZKsync OS that calls `L1Messenger.sendToL1(message)`.
2. Execute the transaction through the bootloader.
3. Inspect `FullIO.events_storage` after the transaction: it contains **zero** entries for the L1 messenger call.
4. Inspect `FullIO.logs_storage`: the message **is** present.
5. An off-chain indexer watching `events_storage` (EVM logs) for `L1MessageSent` events will see nothing, while the message is silently committed to the batch — confirming the event omission. [6](#0-5) [7](#0-6)

### Citations

**File:** basic_system/src/system_implementation/system/io_subsystem.rs (L150-183)
```rust
    fn emit_event(
        &mut self,
        ee_type: ExecutionEnvironmentType,
        resources: &mut Self::Resources,
        address: &<Self::IOTypes as SystemIOTypesConfig>::Address,
        topics: &arrayvec::ArrayVec<
            <Self::IOTypes as SystemIOTypesConfig>::EventKey,
            MAX_EVENT_TOPICS,
        >,
        data: &[u8],
    ) -> Result<(), SystemError> {
        // Charge resources
        let ergs = match ee_type {
            ExecutionEnvironmentType::NoEE => Ergs::empty(),
            ExecutionEnvironmentType::EVM => {
                let static_cost = LOG;
                let topic_cost = LOGTOPIC * (topics.len() as u64);
                let len_cost = (data.len() as u64) * LOGDATA;
                let cost = static_cost + topic_cost + len_cost;
                let ergs = cost.checked_mul(ERGS_PER_GAS).ok_or(out_of_ergs_error!())?;
                Ergs(ergs)
            }
        };
        let native = R::Native::from_computational(
            EVENT_STORAGE_BASE_NATIVE_COST
                + EVENT_TOPIC_NATIVE_COST * (topics.len() as u64)
                + EVENT_DATA_PER_BYTE_COST * (data.len() as u64),
        );
        resources.charge(&R::from_ergs_and_native(ergs, native))?;

        let data = UsizeAlignedByteBox::from_slice_in(data, self.allocator.clone());
        self.events_storage
            .push_event(self.tx_number, address, topics, data)
    }
```

**File:** basic_system/src/system_implementation/system/io_subsystem.rs (L185-228)
```rust
    fn emit_l1_message(
        &mut self,
        _ee_type: ExecutionEnvironmentType,
        resources: &mut Self::Resources,
        address: &<Self::IOTypes as SystemIOTypesConfig>::Address,
        data: &[u8],
    ) -> Result<Bytes32, SystemError> {
        // TODO(EVM-1077): consider adding COMPUTATIONAL_PRICE_FOR_PUBDATA as in Era

        // We need to charge cost of hashing:
        // - keccak256_native_cost(L2_TO_L1_LOG_SERIALIZE_SIZE) and
        //   keccak256_native_cost(64) when reconstructing L2ToL1Log
        // - keccak256_native_cost(64) + keccak256_native_cost(data.len())
        //   when reconstructing Messages
        // - at most 1 time keccak256_native_cost(64) when building the
        //   Merkle tree (as merkle tree can contain ~2*N nodes, where the
        //   first N nodes are leaves the hash of which is calculated on the
        //   previous step).

        let hashing_native_cost =
            keccak256_native_cost::<Self::Resources>(L2_TO_L1_LOG_SERIALIZE_SIZE).as_u64()
                + 3 * keccak256_native_cost::<Self::Resources>(64).as_u64()
                + keccak256_native_cost::<Self::Resources>(data.len()).as_u64();

        // We also charge some native resource for storing the log
        let native = hashing_native_cost
            + EVENT_STORAGE_BASE_NATIVE_COST
            + EVENT_DATA_PER_BYTE_COST * (data.len() as u64);

        resources.charge(&R::from_native(R::Native::from_computational(native)))?;

        // TODO(EVM-1078): for Era backward compatibility we may need to add events for l2 to l1 log and l1 message

        // Compute data hash directly: the native cost for this keccak is already
        // pre-charged above (included in `hashing_native_cost`), and this function
        // must not charge ergs — EVM gas accounting is the caller's responsibility
        // (the L1Messenger system contract charges it before invoking the hook).
        use crypto::MiniDigest;
        let data_hash = Bytes32::from_array(crypto::sha3::Keccak256::digest(data));
        let data = UsizeAlignedByteBox::from_slice_in(data, self.allocator.clone());
        self.logs_storage
            .push_message(self.tx_number, address, data, data_hash)?;
        Ok(data_hash)
    }
```

**File:** system_hooks/src/call_hooks/l1_messenger.rs (L22-55)
```rust
pub fn l1_messenger_hook<'a, S: EthereumLikeTypes>(
    request: ExternalCallRequest<S>,
    caller_ee: u8,
    system: &mut System<S>,
    return_memory: &'a mut [MaybeUninit<u8>],
) -> Result<(CompletedExecution<'a, S>, &'a mut [MaybeUninit<u8>]), SystemError>
where
{
    let ExternalCallRequest {
        available_resources,
        ergs_to_pass: _,
        input: calldata,
        call_scratch_space: _,
        nominal_token_value,
        caller,
        callee,
        callers_caller: _,
        modifier,
    } = request;

    debug_assert_eq!(callee, L1_MESSENGER_ADDRESS_HOOK);

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

**File:** system_hooks/src/call_hooks/l1_messenger.rs (L136-163)
```rust
pub(crate) fn send_to_l1_inner<S: EthereumLikeTypes>(
    calldata: &[u8],
    resources: &mut S::Resources,
    system: &mut System<S>,
) -> Result<Result<(), &'static str>, SystemError> {
    if calldata.len() < 20 {
        return Ok(Err(
            "L1 messenger failure: sendToL1 called with invalid calldata",
        ));
    }

    let address_sender = B160::try_from_be_slice(&calldata[0..20]).ok_or(
        SystemError::LeafDefect(internal_error!("Failed to create B160 from 20 byte array")),
    )?;

    let message = &calldata[20..];

    // emit L1 message (ignore returned hash)
    // TODO(EVM-1190): hash calculation is suboptimal, to be refactored in future
    system.io.emit_l1_message(
        // Gas should be charged by the L1Messenger system contract
        ExecutionEnvironmentType::NoEE,
        resources,
        &address_sender,
        message,
    )?;

    Ok(Ok(()))
```

**File:** system_hooks/src/lib.rs (L206-213)
```rust
pub fn add_l1_messenger<S: EthereumLikeTypes, A: Allocator + Clone>(
    hooks: &mut HooksStorage<S, A>,
) -> Result<(), InternalError> {
    hooks.add_call_hook(
        L1_MESSENGER_ADDRESS_HOOK_LOW,
        SystemCallHook::new(l1_messenger_hook),
    )
}
```
