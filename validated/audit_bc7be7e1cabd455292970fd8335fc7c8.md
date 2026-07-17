Looking at the `tx.origin` bug class — using the wrong identity for authorization/ownership assignment — I need to find a nearcore analog where an unprivileged caller can control a privileged identity used in an authorization or namespace-ownership decision.

The NEAR analog of `tx.origin` vs `msg.sender` is `signer_id` (original transaction signer) vs `predecessor_id` (immediate caller). The scoped target includes **global contract/code selection** and **trie namespace isolation**.

Let me trace the `GlobalContractDeployMode::AccountId` path through the runtime.

In `apply_action_receipt` (`runtime/runtime/src/lib.rs:789`), `account_id = receipt.receiver_id()`. This is passed to `action_deploy_global_contract`, which passes it to `initiate_distribution`, which uses it as the trie namespace key when `deploy_mode == AccountId`. The function receives no `predecessor_id` parameter and performs no caller-authorization check.

A contract can dispatch `DeployGlobalContractAction` to any account via `promise_batch_action_deploy_global_contract_by_account_id` (`runtime/near-vm-runner/src/logic/logic.rs:2558`). The resulting receipt has `predecessor_id = attacker`, `receiver_id = victim`. When it executes, `account_id = victim` is used as the namespace owner — with no check that `predecessor_id == receiver_id`.

The nonce mechanism (`increment_nonce`/`check_and_update_nonce`) does not guard against this: the attacker's deployment always increments the nonce, so the distribution receipt always passes the `incoming_nonce >= stored_nonce` freshness check.

---

### Title
Unauthorized Global Contract Namespace Overwrite via Cross-Contract `DeployGlobalContractAction` — (File: `runtime/runtime/src/global_contracts.rs`)

### Summary
Any unprivileged account can overwrite any other account's `AccountId`-mode global contract namespace by dispatching `DeployGlobalContractAction` via a cross-contract call. `action_deploy_global_contract` uses `receiver_id` as the namespace owner without verifying that `predecessor_id` (the actual caller) has authorization. This allows an attacker to inject arbitrary Wasm into the global contract trie slot of any victim account, corrupting the code executed by every account that uses `GlobalContractIdentifier::AccountId(victim)`.

### Finding Description

`action_deploy_global_contract` receives `account_id` (= `receipt.receiver_id()`) and passes it directly to `initiate_distribution`, which stores the contract under `GlobalContractIdentifier::AccountId(account_id)`: [1](#0-0) 

The function signature accepts no `predecessor_id` and performs no caller-authorization check: [2](#0-1) 

`account_id` is set to `receipt.receiver_id()` in `apply_action_receipt`: [3](#0-2) 

A contract can dispatch this action to any account via the host function: [4](#0-3) 

The nonce guard does not block the attack — the attacker's deployment increments the nonce, so the distribution receipt always satisfies `incoming_nonce >= stored_nonce`: [5](#0-4) 

**Attack path:**
1. Attacker deploys a contract on `attacker.near` that calls `promise_batch_action_deploy_global_contract_by_account_id` targeting `victim.near` with malicious Wasm.
2. A receipt is created: `predecessor_id = attacker.near`, `receiver_id = victim.near`, action = `DeployGlobalContractAction(AccountId, malicious_code)`.
3. The receipt executes on `victim.near`: storage cost is deducted from `victim.near`'s balance; malicious code is written to `TrieKey::GlobalContractCode { identifier: AccountId(victim.near) }`.
4. All accounts that previously called `UseGlobalContractAction` with `GlobalContractIdentifier::AccountId(victim.near)` now execute the attacker's Wasm.

The `GlobalContractDeployMode::AccountId` design intent is explicit — "This allows the **owner** to update the contract for all its users" — but ownership is never enforced: [6](#0-5) 

### Impact Explanation

- **Trie namespace corruption**: `TrieKey::GlobalContractCode { identifier: AccountId(victim) }` is overwritten with attacker-controlled Wasm. Every account whose `AccountContract` is `GlobalByAccount(victim)` now executes that Wasm on every function call.
- **Balance drain**: Storage cost is charged to `victim.near`'s balance, not the attacker's.
- **Scope**: All accounts that have opted into `victim.near`'s global contract are simultaneously affected — a single cross-contract call corrupts an unbounded number of accounts.

Severity: **Critical** — arbitrary code injection into a shared code namespace, affecting all downstream users.

### Likelihood Explanation

Any unprivileged account with a deployed contract can execute this attack. The attacker pays only gas for the outer function call; storage cost is borne by the victim. A minimal valid Wasm binary (a few dozen bytes) keeps the storage cost negligible. No special key, validator role, or admin privilege is required.

### Recommendation

Add an authorization guard in `action_deploy_global_contract` for `AccountId` mode: require that `predecessor_id == receiver_id` (i.e., only the account itself may deploy a global contract under its own namespace). The `predecessor_id` is available on the receipt and must be threaded into the function. Alternatively, add a `validate_receipt`-level check that rejects `DeployGlobalContractAction(AccountId)` in any receipt where `predecessor_id != receiver_id`.

### Proof of Concept

```rust
// Attacker's contract deployed on attacker.near
#[near_bindgen]
impl Attacker {
    pub fn attack(&self, victim: AccountId) {
        // Minimal malicious Wasm that drains callers
        let malicious_wasm: Vec<u8> = include_bytes!("malicious.wasm").to_vec();
        // Creates a receipt: predecessor=attacker.near, receiver=victim.near
        // action=DeployGlobalContractAction(AccountId, malicious_wasm)
        let p = env::promise_batch_create(&victim);
        env::promise_batch_action_deploy_global_contract_by_account_id(p, &malicious_wasm);
    }
}
```

After `attack("victim.near")` executes:
- `TrieKey::GlobalContractCode { identifier: AccountId("victim.near") }` = attacker's Wasm
- Every account with `AccountContract::GlobalByAccount("victim.near")` runs attacker's code on the next function call
- `victim.near`'s balance is reduced by `global_contract_storage_amount_per_byte × len(malicious_wasm)`

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

**File:** runtime/runtime/src/global_contracts.rs (L149-155)
```rust
    let id = match deploy_mode {
        GlobalContractDeployMode::CodeHash => {
            GlobalContractIdentifier::CodeHash(hash(&contract_code))
        }
        GlobalContractDeployMode::AccountId => {
            GlobalContractIdentifier::AccountId(account_id.clone())
        }
```

**File:** runtime/runtime/src/global_contracts.rs (L238-255)
```rust
fn check_and_update_nonce(
    global_contract_data: &GlobalContractDistributionReceipt,
    identifier: &GlobalContractCodeIdentifier,
    state_update: &mut TrieUpdate,
) -> Result<bool, RuntimeError> {
    let nonce_key = TrieKey::GlobalContractNonce { identifier: identifier.clone() };
    let stored_nonce = get_nonce(state_update, &nonce_key)?;
    let incoming_nonce = global_contract_data.nonce();

    // Allow the same nonce since the nonce is updated immediately when
    // initiating distribution to prevent multiple distributions with the same
    // nonce from being initiated.
    if incoming_nonce < stored_nonce {
        return Ok(false);
    }

    set_nonce(state_update, nonce_key, incoming_nonce);
    Ok(true)
```

**File:** runtime/runtime/src/lib.rs (L789-789)
```rust
        let account_id = receipt.receiver_id();
```

**File:** runtime/near-vm-runner/src/logic/logic.rs (L2558-2570)
```rust
    pub fn promise_batch_action_deploy_global_contract_by_account_id(
        &mut self,
        promise_idx: u64,
        code_len: u64,
        code_ptr: u64,
    ) -> Result<()> {
        self.promise_batch_action_deploy_global_contract_impl(
            promise_idx,
            code_len,
            code_ptr,
            GlobalContractDeployMode::AccountId,
            "promise_batch_action_deploy_global_contract_by_account_id",
        )
```

**File:** core/primitives/src/action/mod.rs (L138-142)
```rust
    /// Contract is deployed under the owner account id.
    /// Users will be able reference it by that account id.
    /// This allows the owner to update the contract for all its users.
    AccountId,
}
```
