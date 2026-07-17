### Title
Missing Sender Authorization in `DeployGlobalContractAction` with `AccountId` Mode Allows Any Account to Overwrite Another Account's Global Contract - (File: `runtime/runtime/src/global_contracts.rs`)

### Summary

`action_deploy_global_contract` in `runtime/runtime/src/global_contracts.rs` does not verify that the action's predecessor (sender) equals the receiver when `deploy_mode` is `GlobalContractDeployMode::AccountId`. Any unprivileged account can send a `DeployGlobalContract(AccountId)` action to a victim account, overwriting the victim's global contract namespace entry and charging the victim's balance for storage.

### Finding Description

`GlobalContractDeployMode::AccountId` is documented as "This allows the **owner** to update the contract for all its users." The identifier written to the global trie is `GlobalContractIdentifier::AccountId(account_id)`, where `account_id` is the receipt's `receiver_id`.

In `initiate_distribution`, the identifier is derived exclusively from the receiver:

```rust
GlobalContractDeployMode::AccountId => {
    GlobalContractIdentifier::AccountId(account_id.clone())
}
``` [1](#0-0) 

The storage cost is then deducted from the receiver's balance:

```rust
let Some(updated_balance) = account.amount().checked_sub(storage_cost) else {
    result.result = Err(ActionErrorKind::LackBalanceForState { ... });
    return Ok(());
};
account.set_amount(updated_balance);
``` [2](#0-1) 

The action validator `validate_deploy_global_contract_action` only checks contract byte size — no sender-equals-receiver guard exists:

```rust
fn validate_deploy_global_contract_action(
    limit_config: &LimitConfig,
    action: &DeployGlobalContractAction,
) -> Result<(), ActionsValidationError> {
    if action.code.len() as u64 > limit_config.max_contract_size {
        return Err(ActionsValidationError::ContractSizeExceeded { ... });
    }
    Ok(())
}
``` [3](#0-2) 

The `ActorNoPermission` guard (which enforces `sender == receiver` for administrative actions) is explicitly scoped to `DeployContract`, `Stake`, `AddKey`, and `DeleteKey` — `DeployGlobalContract` is absent from that list: [4](#0-3) 

The `action_deploy_global_contract` function signature does not even receive a `predecessor_id` parameter, confirming no authorization check is possible inside it: [5](#0-4) 

### Impact Explanation

An attacker (Alice) constructs a transaction with `signer_id = alice`, `receiver_id = victim`, containing `Action::DeployGlobalContract { code: malicious_wasm, deploy_mode: AccountId }`. Upon execution:

1. The global contract trie key `GlobalContractCode { identifier: AccountId(victim) }` is overwritten with Alice's malicious bytecode.
2. The victim's NEAR balance is debited for `global_contract_storage_amount_per_byte * code_len`.
3. Every account that previously called `UseGlobalContract(AccountId(victim))` now executes Alice's code on their next function call — a full code-identity substitution across all shards.

The corrupted value is the trie entry `TrieKey::GlobalContractCode { identifier: GlobalContractCodeIdentifier::AccountId(victim) }`. [6](#0-5) 

### Likelihood Explanation

Any account with a valid access key and sufficient gas can submit this transaction. No special privilege, validator role, or whitelist membership is required. The only prerequisite is that the victim account has enough balance to cover storage cost (otherwise the action fails with `LackBalanceForState`, but the attacker can still attempt it against any funded account).

### Recommendation

Add a predecessor-equals-receiver guard inside `action_deploy_global_contract` specifically for `AccountId` mode, mirroring the `ActorNoPermission` pattern used for `DeployContract`:

```rust
if deploy_contract.deploy_mode == GlobalContractDeployMode::AccountId
    && predecessor_id != account_id
{
    result.result = Err(ActionErrorKind::ActorNoPermission {
        account_id: account_id.clone(),
        actor_id: predecessor_id.clone(),
    }.into());
    return Ok(());
}
```

`predecessor_id` must be threaded into `action_deploy_global_contract` from the call site in `apply_action_receipt`. Alternatively, gate the `AccountId` mode at the action-validation layer by requiring `receiver_id == signer_id` in `validate_deploy_global_contract_action`.

### Proof of Concept

```
// Attacker: alice.near
// Victim:   bob.near  (has previously deployed a global contract under AccountId mode)

let tx = SignedTransaction::from_actions(
    nonce,
    "alice.near".parse().unwrap(),   // signer_id
    "bob.near".parse().unwrap(),     // receiver_id  ← victim
    &alice_signer,
    vec![Action::DeployGlobalContract(DeployGlobalContractAction {
        code: MALICIOUS_WASM.into(),
        deploy_mode: GlobalContractDeployMode::AccountId,
    })],
    block_hash,
);
```

After inclusion:
- `TrieKey::GlobalContractCode { identifier: AccountId("bob.near") }` → `MALICIOUS_WASM`
- `bob.near` balance reduced by `global_contract_storage_amount_per_byte * MALICIOUS_WASM.len()`
- All accounts whose `AccountContract` is `GlobalByAccount("bob.near")` now execute `MALICIOUS_WASM` [7](#0-6) [8](#0-7)

### Citations

**File:** runtime/runtime/src/global_contracts.rs (L23-31)
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
```

**File:** runtime/runtime/src/global_contracts.rs (L39-49)
```rust
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
```

**File:** runtime/runtime/src/global_contracts.rs (L141-168)
```rust
fn initiate_distribution(
    state_update: &mut TrieUpdate,
    account_id: AccountId,
    contract_code: Arc<[u8]>,
    deploy_mode: &GlobalContractDeployMode,
    current_shard_id: ShardId,
    result: &mut ActionResult,
) -> Result<(), RuntimeError> {
    let id = match deploy_mode {
        GlobalContractDeployMode::CodeHash => {
            GlobalContractIdentifier::CodeHash(hash(&contract_code))
        }
        GlobalContractDeployMode::AccountId => {
            GlobalContractIdentifier::AccountId(account_id.clone())
        }
    };
    // Increment the nonce and write it to state immediately to prevent multiple
    // distributions with the same nonce from being initiated. This requires
    // allowing the same nonce in the freshness check when applying the
    // distribution receipt.
    let nonce = increment_nonce(state_update, &id)?;
    let distribution_receipt =
        GlobalContractDistributionReceipt::new(id, current_shard_id, vec![], contract_code, nonce);
    let distribution_receipts =
        Receipt::new_global_contract_distribution(account_id, distribution_receipt);
    // No need to set receipt_id here, it will be generated as part of apply_action_receipt
    result.new_receipts.push(distribution_receipts);
    Ok(())
```

**File:** runtime/runtime/src/global_contracts.rs (L207-211)
```rust
    let config = apply_state.config.wasm_config.clone();
    let trie_key = TrieKey::GlobalContractCode { identifier };
    let code_len = global_contract_data.code().len() as u64;
    state_update.set(trie_key, global_contract_data.code().to_vec());
    state_update.commit(StateChangeCause::ReceiptProcessing { receipt_hash: receipt.get_hash() });
```

**File:** runtime/runtime/src/action_validation.rs (L127-140)
```rust
/// Validates a single given action.
/// The `mode` only affects nested validation of `Action::Delegate` payloads
fn validate_action_with_mode(
    limit_config: &LimitConfig,
    action: &Action,
    receiver: &AccountId,
    current_protocol_version: ProtocolVersion,
    mode: ValidateReceiptMode,
) -> Result<(), ActionsValidationError> {
    match action {
        Action::CreateAccount(_) => Ok(()),
        Action::DeployContract(a) => validate_deploy_contract_action(limit_config, a),
        Action::DeployGlobalContract(a) => validate_deploy_global_contract_action(limit_config, a),
        Action::UseGlobalContract(a) => validate_use_global_contract_action(a),
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

**File:** chain/jsonrpc/openapi/openrpc.json (L671-695)
```json
          {
            "additionalProperties": false,
            "description": "Administrative actions like `DeployContract`, `Stake`, `AddKey`, `DeleteKey`. can be proceed only if sender=receiver\nor the first TX action is a `CreateAccount` action",
            "properties": {
              "ActorNoPermission": {
                "properties": {
                  "account_id": {
                    "$ref": "#/components/schemas/AccountId"
                  },
                  "actor_id": {
                    "$ref": "#/components/schemas/AccountId"
                  }
                },
                "required": [
                  "account_id",
                  "actor_id"
                ],
                "type": "object"
              }
            },
            "required": [
              "ActorNoPermission"
            ],
            "title": "ActorNoPermission",
            "type": "object"
```
