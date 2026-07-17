### Title
Any contract can overwrite a victim account's `AccountId`-mode global contract and permanently drain their balance — (`runtime/runtime/src/global_contracts.rs`)

---

### Summary

`action_deploy_global_contract` in `runtime/runtime/src/global_contracts.rs` does not enforce that the receipt's `predecessor_id` equals `receiver_id` when `deploy_mode == GlobalContractDeployMode::AccountId`. A malicious contract can create a cross-account promise targeting any victim account and append `DeployGlobalContract(malicious_wasm, AccountId)` to it. The runtime will overwrite the victim's global contract trie entry with attacker-controlled code and permanently burn the victim's balance as the storage fee — with no authorization check anywhere in the call path.

---

### Finding Description

The NEAR protocol documentation explicitly lists the actions that require `predecessor_id == receiver_id`:

> `DeployContract`, `Stake`, `AddKey`, `DeleteKey`, `DeleteAccount`

`DeployGlobalContract` is absent from this list despite the fact that in `AccountId` mode it writes attacker-controlled code under the victim's account ID as the global-contract namespace key.

The execution path is:

1. **Host function** — `promise_batch_action_deploy_global_contract_impl` in `runtime/near-vm-runner/src/wasmtime_runner/logic.rs` accepts any `promise_idx` (which can target any account). It checks only code size and view-mode prohibition; it does not check whether the promise receiver equals the current account.

2. **Action validation** — `validate_deploy_global_contract_action` in `runtime/runtime/src/action_validation.rs` checks only code size. `validate_actions_with_mode` (the only place where a predecessor/receiver equality check could be inserted) has no such check for `DeployGlobalContract`.

3. **Action execution** — `action_deploy_global_contract` in `runtime/runtime/src/global_contracts.rs` deducts `storage_cost` from `account.amount()` (the victim's balance), adds it to `result.tokens_burnt` (permanently burned, not locked), then calls `initiate_distribution` with `account_id.clone()` (the victim's account ID) as the `AccountId`-mode identifier. No predecessor check exists.

4. **Distribution** — `initiate_distribution` stores the identifier as `GlobalContractIdentifier::AccountId(account_id)` and emits a `GlobalContractDistributionReceipt` that propagates the attacker's code to every shard under `TrieKey::GlobalContractCode { identifier: GlobalContractCodeIdentifier::AccountId(victim) }`.

The `CodeHash` mode is not affected because the identifier is derived from the code content itself (content-addressed), so an attacker cannot overwrite a specific victim's namespace.

---

### Impact Explanation

**Corrupted value**: `TrieKey::GlobalContractCode { identifier: GlobalContractCodeIdentifier::AccountId("victim.near") }` is overwritten with attacker-controlled WASM on every shard.

**Downstream accounts**: Every account that previously executed `UseGlobalContract(AccountId("victim.near"))` has its `AccountContract::GlobalByAccount("victim.near")` pointer resolved to the malicious code. On the next function call to any such account, the attacker's WASM executes — enabling fund theft, state corruption, or key exfiltration across an unbounded number of accounts.

**Balance drain**: `victim.near`'s balance is permanently reduced by `global_contract_storage_amount_per_byte × code_len`. This is burned (added to `tokens_burnt`), not locked, so it is unrecoverable.

**Severity**: Critical — one unprivileged contract call corrupts the code identity of an arbitrary number of accounts and permanently drains the victim's balance.

---

### Likelihood Explanation

Any deployed contract can execute this attack. The attacker needs only to:
1. Deploy a contract (standard operation).
2. Call `promise_batch_create("victim.near")` and append `DeployGlobalContract(minimal_malicious_wasm, AccountId)`.
3. The victim must have enough balance to cover the storage cost (easily verified via RPC before attacking; a minimal valid WASM is only a few dozen bytes, making the cost small).

No privileged access, validator role, or special configuration is required.

---

### Recommendation

Add a predecessor-equals-receiver guard for `AccountId` deploy mode, mirroring the existing guard for `DeployContract`, `Stake`, `AddKey`, etc. The fix belongs in `action_deploy_global_contract` (or equivalently in `validate_deploy_global_contract_action` where the `receiver` is already available):

```rust
// In action_deploy_global_contract, before calling initiate_distribution:
if deploy_contract.deploy_mode == GlobalContractDeployMode::AccountId {
    // Only the account itself may publish a global contract under its own AccountId.
    // receipt.predecessor_id() must equal account_id (the receiver).
    if receipt.predecessor_id() != account_id {
        result.result = Err(ActionErrorKind::ActorNoPermission {
            account_id: account_id.clone(),
            actor_id: receipt.predecessor_id().clone(),
        }.into());
        return Ok(());
    }
}
```

Alternatively, add `DeployGlobalContract` (when `deploy_mode == AccountId`) to the list of actions that require `predecessor_id == receiver_id` enforced at the receipt-validation layer in `validate_actions_with_mode`.

---

### Proof of Concept

**Setup**: Alice has deployed a global contract under her account ID (`GlobalContractDeployMode::AccountId`). Bob's account uses it via `UseGlobalContract(AccountId("alice.near"))`.

**Attack**:
```rust
// Inside attacker's contract (deployed at "attacker.near"):
pub fn attack() {
    // Create a promise targeting alice.near
    let promise = env::promise_batch_create("alice.near");
    // Append DeployGlobalContract with malicious code in AccountId mode
    env::promise_batch_action_deploy_global_contract(
        promise,
        &MALICIOUS_WASM,
        GlobalContractDeployMode::AccountId,
    );
}
```

**Result**:
- `TrieKey::GlobalContractCode { identifier: AccountId("alice.near") }` is overwritten with `MALICIOUS_WASM` on all shards.
- Alice's balance is permanently reduced by `global_contract_storage_amount_per_byte × MALICIOUS_WASM.len()`.
- Bob's account (and every other account using `GlobalContractIdentifier::AccountId("alice.near")`) now executes `MALICIOUS_WASM` on every subsequent function call.

**Key code locations**:

Missing predecessor check in `action_deploy_global_contract`: [1](#0-0) 

`initiate_distribution` uses `account_id` (the victim) as the `AccountId` namespace key with no authorization: [2](#0-1) 

`validate_deploy_global_contract_action` checks only code size, no predecessor/receiver equality: [3](#0-2) 

Host function `promise_batch_action_deploy_global_contract_impl` accepts any promise target with no self-check: [4](#0-3) 

Protocol documentation listing actions that require `predecessor_id == receiver_id` — `DeployGlobalContract` is absent: [5](#0-4)

### Citations

**File:** runtime/runtime/src/global_contracts.rs (L23-61)
```rust
pub(crate) fn action_deploy_global_contract(
    state_update: &mut TrieUpdate,
    account: &mut Account,
    account_id: &AccountId,
    apply_state: &ApplyState,
    deploy_contract: &DeployGlobalContractAction,
    result: &mut ActionResult,
) -> Result<(), RuntimeError> {
    let _span = tracing::debug_span!(target: "runtime", "action_deploy_global_contract").entered();

    let storage_cost = apply_state
        .config
        .fees
        .storage_usage_config
        .global_contract_storage_amount_per_byte
        .saturating_mul(deploy_contract.code.len() as u128);
    let Some(updated_balance) = account.amount().checked_sub(storage_cost) else {
        result.result = Err(ActionErrorKind::LackBalanceForState {
            account_id: account_id.clone(),
            amount: storage_cost,
        }
        .into());
        return Ok(());
    };
    result.tokens_burnt =
        result.tokens_burnt.checked_add(storage_cost).ok_or(IntegerOverflowError)?;
    account.set_amount(updated_balance);

    initiate_distribution(
        state_update,
        account_id.clone(),
        deploy_contract.code.clone(),
        &deploy_contract.deploy_mode,
        apply_state.shard_id,
        result,
    )?;

    Ok(())
}
```

**File:** runtime/runtime/src/global_contracts.rs (L149-156)
```rust
    let id = match deploy_mode {
        GlobalContractDeployMode::CodeHash => {
            GlobalContractIdentifier::CodeHash(hash(&contract_code))
        }
        GlobalContractDeployMode::AccountId => {
            GlobalContractIdentifier::AccountId(account_id.clone())
        }
    };
```

**File:** runtime/runtime/src/action_validation.rs (L225-238)
```rust
/// Validates `DeployGlobalContractAction`. Checks that the given contract size doesn't exceed the limit.
fn validate_deploy_global_contract_action(
    limit_config: &LimitConfig,
    action: &DeployGlobalContractAction,
) -> Result<(), ActionsValidationError> {
    if action.code.len() as u64 > limit_config.max_contract_size {
        return Err(ActionsValidationError::ContractSizeExceeded {
            size: action.code.len() as u64,
            limit: limit_config.max_contract_size,
        });
    }

    Ok(())
}
```

**File:** runtime/near-vm-runner/src/wasmtime_runner/logic.rs (L2716-2732)
```rust
    let (receipt_idx, sir) = promise_idx_to_receipt_idx_with_sir(ctx, promise_idx)?;

    pay_action_base(
        &mut ctx.result_state.gas_counter,
        &ctx.fees_config,
        ActionCosts::deploy_global_contract_base,
        sir,
    )?;
    pay_action_per_byte(
        &mut ctx.result_state.gas_counter,
        &ctx.fees_config,
        ActionCosts::deploy_global_contract_byte,
        code_len,
        sir,
    )?;

    ctx.ext.append_action_deploy_global_contract(receipt_idx, code, mode);
```

**File:** docs/RuntimeSpec/Actions.md (L26-33)
```markdown
For the following actions, `predecessor_id` and `receiver_id` are required to be equal:

- `DeployContract`
- `Stake`
- `AddKey`
- `DeleteKey`
- `DeleteAccount`

```
