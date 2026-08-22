### Title
`gas_key_transfer_exec_fee` underprices TransferToGasKey/WithdrawFromGasKey trie writes for GasKeyFunctionCall keys, allowing free storage growth - ([File: core/parameters/src/cost.rs])

### Summary
`gas_key_transfer_exec_fee` charges for the AccessKey value using `AccessKey::min_gas_key_borsh_len()`, which is hard-coded to the size of the smallest possible gas-key variant, `GasKeyFullAccess` [1](#0-0) . But `action_transfer_to_gas_key`/`action_withdraw_from_gas_key` re-serialize and write the *entire* `AccessKey` retrieved from storage back to the trie via `set_access_key`, including whatever permission variant it actually has [2](#0-1) [3](#0-2) . A `GasKeyFunctionCall(GasKeyInfo, FunctionCallPermission)` key can carry a much larger `FunctionCallPermission` with variable-length `receiver_id: String` and `method_names: Vec<String>` [4](#0-3) , so the real trie write byte count exceeds the "min" estimate used for the exec fee.

### Finding Description
`gas_key_transfer_exec_fee` computes the estimated value length as a constant:
```rust
let estimated_value_len = AccessKey::min_gas_key_borsh_len();
``` [5](#0-4) 

`min_gas_key_borsh_len` is defined as the borsh length of `gas_key_full_access(0)` — i.e. `AccessKey { nonce: 0, permission: GasKeyFullAccess(GasKeyInfo{balance:0, num_nonces:0}) }` [1](#0-0) . Both fields inside `GasKeyFullAccess` are fixed-width (`Balance`, `NonceIndex`), so this length is indeed constant for that variant. However, the `AccessKey.permission` enum also has a `GasKeyFunctionCall(GasKeyInfo, FunctionCallPermission)` variant [6](#0-5) , and `FunctionCallPermission` contains an arbitrary-length `receiver_id: String` and `method_names: Vec<String>` [4](#0-3) . This variant's borsh length is strictly larger than, and unrelated to, `min_gas_key_borsh_len()`.

`exec_fee` for `TransferToGasKey`/`WithdrawFromGasKey` calls `gas_key_transfer_exec_fee` unconditionally with this constant estimate, regardless of the actual permission stored for the key being transferred to/withdrawn from [7](#0-6) . The same happens in the VM logic host functions for `promise_batch_action_transfer_to_gas_key`/withdraw variants, which call `gas_key_transfer_exec_fee` the same way [8](#0-7) [9](#0-8) .

At execution time, `action_transfer_to_gas_key` fetches the full `AccessKey` (whatever its permission is) via `get_access_key`, mutates `gas_key_info.balance`, and writes the *whole* `AccessKey` back to the trie via `set_access_key` [10](#0-9) . `action_withdraw_from_gas_key` does the same [11](#0-10) . Since the trie value written is the full borsh encoding of the stored `AccessKey`, and the fee model always assumes the minimal `GasKeyFullAccess` size, an attacker who created a gas key with `GasKeyFunctionCall` permission and a large `receiver_id`/`method_names` list can trigger trie writes whose actual byte count is far larger than what is charged by `gas_key_transfer_exec_fee`'s per-byte component every time they call `TransferToGasKey` or `WithdrawFromGasKey`.

Note: the `AddKey` action that creates such a key does charge separately via `permission_send_fees`/`gas_key_add_key_send_fee` for the `method_names` bytes at add-key time [12](#0-11) , but that only prices the one-time key creation. It does not affect, and is disconnected from, the per-call exec fee charged on every subsequent `TransferToGasKey`/`WithdrawFromGasKey`, which is the object of this question and always uses the constant minimal estimate.

### Impact Explanation
This is a storage/gas metering bypass: repeated `TransferToGasKey`/`WithdrawFromGasKey` calls on a `GasKeyFunctionCall`-permissioned gas key write more trie bytes than are charged for, letting an attacker perform underpriced (partially free) storage-affecting operations repeatedly. This falls under NEAR's "gas or storage metering bypass" impact class from the audit scope.

### Likelihood Explanation
Fully reachable by an unprivileged account holder: create an account, use `AddKey`/`promise_batch_action_add_key_with_gas_key_function_call` (or equivalent) to add a gas key with `GasKeyFunctionCall` permission with a large `receiver_id` and/or many `method_names`, then repeatedly call `TransferToGasKey`/`WithdrawFromGasKey` (directly or via a contract calling `promise_batch_action_transfer_to_gas_key`/`withdraw_from_gas_key`). No special privileges or gating found blocking this; the exec-fee computation in `gas_key_transfer_exec_fee` is unconditional on permission type.

### Recommendation
Compute `estimated_value_len` in `gas_key_transfer_exec_fee` (and in the call sites in `runtime/runtime/src/config.rs::exec_fee` and the VM logic host functions) from the actual serialized length of the stored `AccessKey`/permission (or from a true worst-case upper bound covering `GasKeyFunctionCall` with its `FunctionCallPermission`), rather than always using `AccessKey::min_gas_key_borsh_len()`. At minimum, pass the actual `borsh::object_length(&access_key)` value into the fee function at the point where the access key is fetched in `action_transfer_to_gas_key`/`action_withdraw_from_gas_key`, and use that for post-hoc accounting, or charge based on a fixed maximum-size upper bound (bounding `method_names`/`receiver_id` size) rather than a minimum.

### Proof of Concept
Unit/integration test plan (in `runtime/runtime/src/access_keys.rs` tests or a new property test in `core/parameters/src/cost.rs`):
1. Construct an `AccessKey` with `permission: AccessKeyPermission::GasKeyFunctionCall(GasKeyInfo{...}, FunctionCallPermission{ allowance: None, receiver_id: "a".repeat(64), method_names: vec!["m".repeat(64); N] })`.
2. Assert `borsh::object_length(&access_key).unwrap() > AccessKey::min_gas_key_borsh_len()` (demonstrates the "min" is not an upper bound).
3. Set up an account with this gas key via `add_gas_key_to_account`, call `action_transfer_to_gas_key`, and record the actual bytes written to the trie for the `AccessKey` value (via `state_update`/trie changes) versus the `per_byte` component computed by `gas_key_transfer_exec_fee(cfg, account_id.len(), public_key.trie_id_len())` using `estimated_value_len`.
4. Assert that actual trie bytes written > bytes charged by the fee function, proving metering incompleteness (charge < real bytes written) for every `TransferToGasKey`/`WithdrawFromGasKey` call on such a key.

### Citations

**File:** core/primitives-core/src/account.rs (L483-487)
```rust
    /// Minimum borsh-serialized size of an AccessKey with a gas key permission.
    /// This is the size for GasKeyFullAccess (the smallest gas key variant).
    pub fn min_gas_key_borsh_len() -> usize {
        borsh::object_length(&Self::gas_key_full_access(0)).unwrap()
    }
```

**File:** core/primitives-core/src/account.rs (L580-586)
```rust
    /// Gas key with limited permission to make transactions with FunctionCallActions
    /// Gas keys are a kind of access keys with a prepaid balance to pay for gas.
    GasKeyFunctionCall(GasKeyInfo, FunctionCallPermission),
    /// Gas key with full access to the account.
    /// Gas keys are a kind of access keys with a prepaid balance to pay for gas.
    GasKeyFullAccess(GasKeyInfo),
}
```

**File:** core/primitives-core/src/account.rs (L625-644)
```rust
pub struct FunctionCallPermission {
    /// Allowance is a balance limit to use by this access key to pay for function call gas and
    /// transaction fees. When this access key is used, both account balance and the allowance is
    /// decreased by the same value.
    /// `None` means unlimited allowance.
    /// NOTE: To change or increase the allowance, the old access key needs to be deleted and a new
    /// access key should be created.
    pub allowance: Option<Balance>,

    // This isn't an AccountId because already existing records in testnet genesis have invalid
    // values for this field (see: https://github.com/near/nearcore/pull/4621#issuecomment-892099860)
    // we accommodate those by using a string, allowing us to read and parse genesis.
    /// The access key only allows transactions with the given receiver's account id.
    pub receiver_id: String,

    /// A list of method names that can be used. The access key only allows transactions with the
    /// function call of one of the given method names.
    /// Empty list means any method name can be used.
    pub method_names: Vec<String>,
}
```

**File:** runtime/runtime/src/access_keys.rs (L257-288)
```rust
pub(crate) fn action_transfer_to_gas_key(
    state_update: &mut TrieUpdate,
    result: &mut ActionResult,
    account_id: &AccountId,
    action: &TransferToGasKeyAction,
) -> Result<(), RuntimeError> {
    let Some(mut access_key) = get_access_key(state_update, account_id, &action.public_key)? else {
        result.result = Err(ActionErrorKind::GasKeyDoesNotExist {
            account_id: account_id.clone(),
            public_key: Box::new(action.public_key.clone()),
        }
        .into());
        return Ok(());
    };
    let Some(gas_key_info) = access_key.gas_key_info_mut() else {
        // Key exists but is not a gas key
        result.result = Err(ActionErrorKind::GasKeyDoesNotExist {
            account_id: account_id.clone(),
            public_key: Box::new(action.public_key.clone()),
        }
        .into());
        return Ok(());
    };

    gas_key_info.balance = gas_key_info.balance.checked_add(action.deposit).ok_or_else(|| {
        RuntimeError::StorageError(StorageError::StorageInconsistentState(
            "gas key balance integer overflow".to_string(),
        ))
    })?;
    set_access_key(state_update, account_id.clone(), action.public_key.clone(), &access_key);
    Ok(())
}
```

**File:** runtime/runtime/src/access_keys.rs (L290-335)
```rust
pub(crate) fn action_withdraw_from_gas_key(
    state_update: &mut TrieUpdate,
    account: &mut Account,
    result: &mut ActionResult,
    account_id: &AccountId,
    action: &WithdrawFromGasKeyAction,
) -> Result<(), RuntimeError> {
    let Some(mut access_key) = get_access_key(state_update, account_id, &action.public_key)? else {
        result.result = Err(ActionErrorKind::GasKeyDoesNotExist {
            account_id: account_id.clone(),
            public_key: Box::new(action.public_key.clone()),
        }
        .into());
        return Ok(());
    };
    let Some(gas_key_info) = access_key.gas_key_info_mut() else {
        // Key exists but is not a gas key
        result.result = Err(ActionErrorKind::GasKeyDoesNotExist {
            account_id: account_id.clone(),
            public_key: Box::new(action.public_key.clone()),
        }
        .into());
        return Ok(());
    };

    let Some(updated_balance) = gas_key_info.balance.checked_sub(action.amount) else {
        result.result = Err(ActionErrorKind::InsufficientGasKeyBalance {
            account_id: account_id.clone(),
            public_key: Box::new(action.public_key.clone()),
            balance: gas_key_info.balance,
            required: action.amount,
        }
        .into());
        return Ok(());
    };
    gas_key_info.balance = updated_balance;
    set_access_key(state_update, account_id.clone(), action.public_key.clone(), &access_key);

    let new_account_balance = account.amount().checked_add(action.amount).ok_or_else(|| {
        RuntimeError::StorageError(StorageError::StorageInconsistentState(
            "Account balance integer overflow".to_string(),
        ))
    })?;
    account.set_amount(new_account_balance);
    Ok(())
}
```

**File:** core/parameters/src/cost.rs (L833-847)
```rust
pub fn gas_key_transfer_exec_fee(
    cfg: &RuntimeFeesConfig,
    account_id_len: usize,
    public_key_len: usize,
) -> GasKeyTransferFee {
    let base = cfg.fee(ActionCosts::gas_key_transfer_base).exec_fee();
    let trie_key_len = access_key_key_len(account_id_len, public_key_len);
    let estimated_value_len = AccessKey::min_gas_key_borsh_len();
    let per_byte = cfg
        .fee(ActionCosts::gas_key_byte)
        .exec_fee()
        .checked_mul((trie_key_len + estimated_value_len) as u64)
        .unwrap();
    GasKeyTransferFee { base, per_byte }
}
```

**File:** runtime/runtime/src/config.rs (L201-233)
```rust
fn permission_send_fees(
    permission: &AccessKeyPermission,
    fees: &RuntimeFeesConfig,
    sender_is_receiver: bool,
) -> ParameterCost {
    let key_fee = match permission {
        AccessKeyPermission::FunctionCall(perm)
        | AccessKeyPermission::GasKeyFunctionCall(_, perm) => {
            let num_bytes = perm
                .method_names
                .iter()
                // Account for null-terminating characters.
                .map(|name| name.as_bytes().len() as u64 + 1)
                .sum::<u64>();
            let base_fee =
                fees.fee(ActionCosts::add_function_call_key_base).send_fee(sender_is_receiver);
            let byte_fee =
                fees.fee(ActionCosts::add_function_call_key_byte).send_fee(sender_is_receiver);
            let all_bytes_fee = byte_fee.checked_mul(num_bytes).unwrap();
            base_fee.checked_add(all_bytes_fee).unwrap()
        }
        AccessKeyPermission::FullAccess | AccessKeyPermission::GasKeyFullAccess(_) => {
            fees.fee(ActionCosts::add_full_access_key).send_fee(sender_is_receiver)
        }
    };
    let gas_key_info_fee = match permission {
        AccessKeyPermission::GasKeyFunctionCall(..) | AccessKeyPermission::GasKeyFullAccess(_) => {
            gas_key_add_key_send_fee(fees, sender_is_receiver)
        }
        _ => ParameterCost::ZERO,
    };
    key_fee.checked_add(gas_key_info_fee).unwrap()
}
```

**File:** runtime/runtime/src/config.rs (L347-354)
```rust
        TransferToGasKey(action) => {
            gas_key_transfer_exec_fee(fees, receiver_id.len(), action.public_key.trie_id_len())
                .total()
        }
        WithdrawFromGasKey(action) => {
            gas_key_transfer_exec_fee(fees, receiver_id.len(), action.public_key.trie_id_len())
                .total()
        }
```

**File:** runtime/near-vm-runner/src/logic/logic.rs (L3092-3096)
```rust
        let exec = gas_key_transfer_exec_fee(
            &self.fees_config,
            receiver_id.len(),
            public_key_len as usize,
        );
```

**File:** runtime/near-vm-runner/src/wasmtime_runner/logic.rs (L3324-3325)
```rust
    let exec =
        gas_key_transfer_exec_fee(&ctx.fees_config, receiver_id.len(), public_key_len as usize);
```
