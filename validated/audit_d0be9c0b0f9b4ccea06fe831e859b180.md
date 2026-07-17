### Title
Unauthorized Global Contract Overwrite via Missing Signer-Receiver Identity Check in `AccountId` Deploy Mode — (File: `runtime/runtime/src/global_contracts.rs`)

---

### Summary

`action_deploy_global_contract` does not verify that the transaction signer (`signer_id`) equals the receipt receiver (`receiver_id`) when `GlobalContractDeployMode::AccountId` is used. Because any NEAR account can send a transaction targeting an arbitrary `receiver_id`, an unprivileged attacker can overwrite a victim account's global contract entry (stored under the victim's `AccountId` in the global trie namespace) with attacker-controlled code, and simultaneously drain the victim's balance by the storage cost — without the victim's consent.

---

### Finding Description

**Invariant that must hold:** Only the account that owns an `AccountId` may publish or update the global contract stored under that `AccountId`.

**Root cause — `action_deploy_global_contract` (lines 23–61):**

```rust
pub(crate) fn action_deploy_global_contract(
    state_update: &mut TrieUpdate,
    account: &mut Account,
    account_id: &AccountId,          // ← this is receipt.receiver_id, NOT signer_id
    apply_state: &ApplyState,
    deploy_contract: &DeployGlobalContractAction,
    result: &mut ActionResult,
) -> Result<(), RuntimeError> {
    ...
    initiate_distribution(
        state_update,
        account_id.clone(),          // ← used as the AccountId key in AccountId mode
        deploy_contract.code.clone(),
        &deploy_contract.deploy_mode,
        apply_state.shard_id,
        result,
    )?;
    Ok(())
}
``` [1](#0-0) 

Inside `initiate_distribution`, when `deploy_mode == AccountId`, the global contract is keyed by `account_id` (the receiver):

```rust
GlobalContractDeployMode::AccountId => {
    GlobalContractIdentifier::AccountId(account_id.clone())
}
``` [2](#0-1) 

**No authorization check exists anywhere in the call path.** The action validator `validate_deploy_global_contract_action` only checks code size:

```rust
Action::DeployGlobalContract(a) => validate_deploy_global_contract_action(limit_config, a),
``` [3](#0-2) 

There is no `signer_id == receiver_id` guard in `validate_deploy_global_contract_action`, in `action_deploy_global_contract`, or anywhere in `apply_action` before the call is dispatched.

In NEAR, a transaction may have `signer_id ≠ receiver_id`. The signer only needs a valid access key on their own account; the receiver does not authorize the transaction. The actions execute on the receiver's account, and the storage cost is debited from the receiver's balance:

```rust
let Some(updated_balance) = account.amount().checked_sub(storage_cost) else {
    result.result = Err(ActionErrorKind::LackBalanceForState { ... });
    return Ok(());
};
account.set_amount(updated_balance);
``` [4](#0-3) 

The nonce mechanism (`increment_nonce` / `check_and_update_nonce`) only prevents stale distribution receipts from overwriting a newer version; it does not prevent a fresh deployment from a different signer from overwriting the victim's entry with a higher nonce. [5](#0-4) 

---

### Impact Explanation

**Corrupted values:**

1. `TrieKey::GlobalContractCode { identifier: GlobalContractCodeIdentifier::AccountId(victim) }` — overwritten with attacker-supplied bytecode.
2. `account.amount()` for the victim account — reduced by `global_contract_storage_amount_per_byte × code.len()` (up to 4 MiB × rate).

**Downstream effect:** Every account that has called `UseGlobalContractAction` with `GlobalContractIdentifier::AccountId(victim)` now executes the attacker's code on the next function call. This enables theft of attached deposits, manipulation of cross-contract state, and arbitrary logic execution under the victim's identity — a Critical impact on the global contract/code selection scope.

---

### Likelihood Explanation

The attack requires only a standard signed transaction from any funded account. No validator, block-producer, or privileged role is needed. The `DeployGlobalContractAction` action type is accepted in the same transaction format as any other action. The attacker pays only gas; the victim pays the storage cost. The attack is repeatable and can be automated.

---

### Recommendation

Add an authorization guard in `action_deploy_global_contract` (or in `validate_deploy_global_contract_action` by threading `signer_id` and `receiver_id` through) that rejects `AccountId` mode deployments when `signer_id ≠ receiver_id`:

```rust
if matches!(deploy_contract.deploy_mode, GlobalContractDeployMode::AccountId)
    && action_receipt.signer_id() != account_id
{
    result.result = Err(ActionErrorKind::ActorNoPermission {
        account_id: account_id.clone(),
        actor_id: action_receipt.signer_id().clone(),
    }.into());
    return Ok(());
}
```

This mirrors the existing pattern used for `DeleteAccount` and other privileged actions that require the actor to be the receiver.

---

### Proof of Concept

1. **Setup:** Victim account `bob.near` deploys a global contract under `AccountId` mode. Many accounts call `UseGlobalContractAction { contract_identifier: AccountId("bob.near") }` to point their execution at `bob.near`'s contract.

2. **Attack transaction (signed by `alice.near`):**
   ```
   signer_id   = "alice.near"
   receiver_id = "bob.near"
   actions     = [DeployGlobalContractAction {
       code: <malicious_wasm>,
       deploy_mode: AccountId,
   }]
   ```

3. **Execution:** `apply_action_receipt` sets `account_id = "bob.near"`. `action_deploy_global_contract` is called with `account_id = "bob.near"`. `initiate_distribution` creates `GlobalContractIdentifier::AccountId("bob.near")` and writes the malicious code to `TrieKey::GlobalContractCode { identifier: AccountId("bob.near") }`. `bob.near`'s balance is debited by the storage cost.

4. **Effect:** All accounts using `GlobalContractIdentifier::AccountId("bob.near")` now execute `alice.near`'s malicious bytecode on their next function call. `alice.near` pays only gas; `bob.near` pays the storage cost and loses control of the code executed on behalf of all its users.

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

**File:** runtime/runtime/src/global_contracts.rs (L171-187)
```rust
/// Increments the nonce for the given global contract identifier and writes
/// it to state immediately.
fn increment_nonce(
    state_update: &mut TrieUpdate,
    id: &GlobalContractIdentifier,
) -> Result<u64, RuntimeError> {
    let identifier: GlobalContractCodeIdentifier = id.clone().into();

    let nonce_key = TrieKey::GlobalContractNonce { identifier };
    let stored_nonce = get_nonce(state_update, &nonce_key)?;

    let new_nonce = stored_nonce.checked_add(1).ok_or_else(|| {
        RuntimeError::UnexpectedIntegerOverflow("increment_global_contract_nonce".into())
    })?;
    set_nonce(state_update, nonce_key, new_nonce);
    Ok(new_nonce)
}
```

**File:** runtime/runtime/src/action_validation.rs (L139-139)
```rust
        Action::DeployGlobalContract(a) => validate_deploy_global_contract_action(limit_config, a),
```
