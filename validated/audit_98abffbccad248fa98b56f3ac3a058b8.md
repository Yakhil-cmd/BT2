### Title
Unauthorized Overwrite of `AccountId`-Mode Global Contract via Cross-Contract Call — (`runtime/runtime/src/global_contracts.rs`)

### Summary

`action_deploy_global_contract` in `runtime/runtime/src/global_contracts.rs` performs no authorization check verifying that the receipt's `predecessor_id` equals the `account_id` (receiver) when deploying in `GlobalContractDeployMode::AccountId` mode. Any deployed contract can craft a cross-contract receipt targeting `victim.near` with a `DeployGlobalContractByAccountId` action carrying attacker-controlled WASM. When applied, the runtime stores the malicious code under `TrieKey::GlobalContractCode { identifier: AccountId("victim.near") }`, silently replacing the code executed by every account that previously called `UseGlobalContract(AccountId("victim.near"))`.

### Finding Description

`GlobalContractDeployMode::AccountId` is explicitly documented as "allows the owner to update the contract for all its users." The invariant is that only the account whose ID is the key may write to that slot. The runtime enforces no such invariant.

**Root cause — `action_deploy_global_contract`:**

```rust
// runtime/runtime/src/global_contracts.rs  lines 23-61
pub(crate) fn action_deploy_global_contract(
    state_update: &mut TrieUpdate,
    account: &mut Account,
    account_id: &AccountId,          // = receipt.receiver_id()
    apply_state: &ApplyState,
    deploy_contract: &DeployGlobalContractAction,
    result: &mut ActionResult,
) -> Result<(), RuntimeError> {
    // Only check: does the receiver have enough balance?
    let Some(updated_balance) = account.amount().checked_sub(storage_cost) else { … };
    …
    initiate_distribution(state_update, account_id.clone(), …, &deploy_contract.deploy_mode, …)?;
}
``` [1](#0-0) 

Inside `initiate_distribution`, when the mode is `AccountId`, the trie key is derived from `account_id` — the receipt's `receiver_id`, not the `predecessor_id`:

```rust
// lines 149-156
let id = match deploy_mode {
    GlobalContractDeployMode::AccountId => {
        GlobalContractIdentifier::AccountId(account_id.clone())  // receiver, not sender
    }
    …
};
``` [2](#0-1) 

There is no guard of the form `if receipt.predecessor_id() != account_id { return Err(Unauthorized) }`.

**Attacker-controlled path:**

The host functions `promise_batch_action_deploy_global_contract_by_account_id` (both the interpreter-based and wasmtime-based implementations) allow any executing contract to append a `DeployGlobalContract(AccountId mode)` action to a receipt targeting an arbitrary account:

```rust
// runtime/near-vm-runner/src/logic/logic.rs  lines 2573-2599
fn promise_batch_action_deploy_global_contract_impl(…, mode: GlobalContractDeployMode, …) {
    …
    let (receipt_idx, sir) = self.promise_idx_to_receipt_idx_with_sir(promise_idx)?;
    self.pay_action_base(ActionCosts::deploy_global_contract_base, sir)?;
    self.pay_action_per_byte(ActionCosts::deploy_global_contract_byte, code_len, sir)?;
    self.ext.append_action_deploy_global_contract(receipt_idx, code, mode);  // no auth check
}
``` [3](#0-2) 

The only runtime guard at action-application time is `check_account_existence`, which only verifies the target account exists:

```rust
// runtime/runtime/src/actions.rs  lines 806-823
Action::DeployGlobalContract(_) | … => {
    if account.is_none() {
        return Err(ActionErrorKind::AccountDoesNotExist { … }.into());
    }
}
``` [4](#0-3) 

**Corrupted state value:**

`apply_distribution_current_shard` writes the attacker-supplied bytes directly to `TrieKey::GlobalContractCode { identifier: AccountId("victim.near") }`:

```rust
// runtime/runtime/src/global_contracts.rs  lines 208-211
let trie_key = TrieKey::GlobalContractCode { identifier };
state_update.set(trie_key, global_contract_data.code().to_vec());
state_update.commit(…);
``` [5](#0-4) 

Every account that previously called `UseGlobalContract(AccountId("victim.near"))` stores `AccountContract::GlobalByAccount("victim.near")` in its own state. On the next function call, `RuntimeContractIdentifier::resolve` resolves that pointer to the now-attacker-controlled code hash and executes it. [6](#0-5) 

### Impact Explanation

All accounts that have opted into `UseGlobalContract(AccountId("victim.near"))` silently begin executing attacker-controlled WASM on every subsequent function call. The attacker's code can drain balances, corrupt storage, or exfiltrate data from every such account. The victim deployer cannot recover: the attacker can keep re-overwriting the slot (each overwrite increments the nonce, so the victim's own re-deploy would need a higher nonce, but the attacker can race again). This is a permanent, protocol-level code-identity substitution affecting an unbounded number of accounts — analogous to destroying the shared implementation contract in the Vault proxy pattern.

### Likelihood Explanation

The attack requires only: (1) deploying a contract (any unprivileged account can do this), (2) calling `promise_batch_create("victim.near")` and appending `DeployGlobalContractByAccountId` with malicious WASM. The storage cost is charged to `victim.near`'s balance, not the attacker's. If `victim.near` holds any balance (which it must, having paid to deploy the global contract originally), the action succeeds. No validator or operator privilege is required.

### Recommendation

Add an authorization check inside `action_deploy_global_contract` for `AccountId` mode, verifying that the receipt's `predecessor_id` equals the `account_id` (receiver):

```rust
if let GlobalContractDeployMode::AccountId = &deploy_contract.deploy_mode {
    if receipt.predecessor_id() != account_id {
        result.result = Err(ActionErrorKind::ActorNoPermission {
            account_id: account_id.clone(),
            actor_id: receipt.predecessor_id().clone(),
        }.into());
        return Ok(());
    }
}
```

Alternatively, restrict `DeployGlobalContract(AccountId mode)` to self-receipts only (where `signer_id == receiver_id`) at the transaction-validation layer.

### Proof of Concept

```rust
// Attacker's contract (deployed at attacker.near)
#[near_bindgen]
impl AttackerContract {
    pub fn overwrite_victim_global_contract(&self) {
        // malicious WASM that drains caller's balance
        let malicious_wasm: Vec<u8> = include_bytes!("malicious.wasm").to_vec();

        // Create a receipt targeting victim.near
        let promise = env::promise_batch_create("victim.near");
        // Append DeployGlobalContract(AccountId mode) — no authorization check exists
        env::promise_batch_action_deploy_global_contract_by_account_id(
            promise,
            &malicious_wasm,
        );
    }
}
```

After `attacker.near` calls `overwrite_victim_global_contract()`:
1. A receipt is created: `predecessor=attacker.near`, `receiver=victim.near`, action=`DeployGlobalContract(AccountId, malicious_wasm)`
2. `action_deploy_global_contract` is called with `account_id="victim.near"` — no auth check fires
3. `TrieKey::GlobalContractCode { identifier: AccountId("victim.near") }` is overwritten with `malicious_wasm`
4. Every account holding `AccountContract::GlobalByAccount("victim.near")` now executes `malicious_wasm` on the next function call

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

**File:** runtime/runtime/src/global_contracts.rs (L208-211)
```rust
    let trie_key = TrieKey::GlobalContractCode { identifier };
    let code_len = global_contract_data.code().len() as u64;
    state_update.set(trie_key, global_contract_data.code().to_vec());
    state_update.commit(StateChangeCause::ReceiptProcessing { receipt_hash: receipt.get_hash() });
```

**File:** runtime/near-vm-runner/src/logic/logic.rs (L2573-2599)
```rust
    fn promise_batch_action_deploy_global_contract_impl(
        &mut self,
        promise_idx: u64,
        code_len: u64,
        code_ptr: u64,
        mode: GlobalContractDeployMode,
        method_name: &str,
    ) -> Result<()> {
        self.result_state.gas_counter.pay_base(base)?;
        if self.context.is_view() {
            return Err(HostError::ProhibitedInView { method_name: method_name.to_owned() }.into());
        }
        let code = get_memory_or_register!(self, code_ptr, code_len)?;
        let code_len = code.len() as u64;
        let limit = self.config.limit_config.max_contract_size;
        if code_len > limit {
            return Err(HostError::ContractSizeExceeded { size: code_len, limit }.into());
        }
        let code = code.into_owned();

        let (receipt_idx, sir) = self.promise_idx_to_receipt_idx_with_sir(promise_idx)?;

        self.pay_action_base(ActionCosts::deploy_global_contract_base, sir)?;
        self.pay_action_per_byte(ActionCosts::deploy_global_contract_byte, code_len, sir)?;

        self.ext.append_action_deploy_global_contract(receipt_idx, code, mode);
        Ok(())
```

**File:** runtime/runtime/src/actions.rs (L806-823)
```rust
        Action::DeployContract(_)
        | Action::FunctionCall(_)
        | Action::Stake(_)
        | Action::AddKey(_)
        | Action::DeleteKey(_)
        | Action::DeleteAccount(_)
        | Action::Delegate(_)
        | Action::DelegateV2(_)
        | Action::DeployGlobalContract(_)
        | Action::UseGlobalContract(_)
        | Action::TransferToGasKey(_)
        | Action::WithdrawFromGasKey(_) => {
            if account.is_none() {
                return Err(ActionErrorKind::AccountDoesNotExist {
                    account_id: account_id.clone(),
                }
                .into());
            }
```

**File:** runtime/runtime/src/contract_code.rs (L43-46)
```rust
        let local_hash = match GlobalContractIdentifier::try_from(account_contract) {
            Ok(gci) => {
                let code_hash = gci.clone().hash(state_update, access)?;
                return Ok(RuntimeContractIdentifier::Global { code_hash, identifier: gci });
```
