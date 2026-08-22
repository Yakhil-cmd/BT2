### Title
Unprivileged donation to a victim's gas key can permanently block key/account deletion (griefing / fund lock) - ([File: runtime/runtime/src/access_keys.rs])

### Summary
The `TransferToGasKeyAction` handler lets **any account** top up the balance of **another account's** gas key with no ownership or consent check. Because gas keys have a hard cap (`GasKeyInfo::MAX_BALANCE_TO_BURN` = 1 NEAR) on the balance that can be burned during `DeleteKey`/`DeleteAccount`, an attacker who knows (or observes on-chain via `ViewAccessKeyList`) a victim's gas key public key can donate funds to push its balance above that cap. This mirrors the DCA "donate negligible tokens to keep the trigger true" pattern from the external report: the attacker controls a balance-threshold check that the victim did not consent to change, and uses it to force an unwanted state (here, a permanent inability to delete/exit) rather than a beneficial one.

### Finding Description
`action_transfer_to_gas_key` credits `account.deposit` to the gas key identified by `action.public_key` on `account_id` (the receipt's receiver) with **no check that the predecessor/actor equals `account_id`**: [1](#0-0) 

Any signed transaction (or contract-issued receipt) whose `receiver_id` is the victim account and whose action list contains `Action::TransferToGasKey { public_key: <victim's gas key>, deposit: <any amount> }` will succeed and silently increase that gas key's balance — exactly like an ERC20 "donation" to someone else's balance.

Gas keys enforce a strict ceiling on the balance that can be burned when deleting the key (`action_delete_key`/`delete_gas_key`) or the whole account (`action_delete_account`): [2](#0-1) [3](#0-2) [4](#0-3) 

If the summed gas-key balance(s) on the account exceed 1 NEAR, both `DeleteKey` (for that key) and `DeleteAccount` (aggregate over all gas keys, via `compute_gas_key_balance_sum`) fail with `ActionErrorKind::GasKeyBalanceTooHigh`: [5](#0-4) 

Because `TransferToGasKeyAction` has no authorization restriction, an attacker can:
1. Query the victim's access keys (`ViewAccessKeyList`) to learn a gas-key public key.
2. Send one or more `TransferToGasKeyAction` transactions/receipts targeting that key, cumulatively pushing its balance above `MAX_BALANCE_TO_BURN`.
3. The victim is now permanently unable to `DeleteKey` that gas key or `DeleteAccount` (until/unless the balance is drawn back down below the threshold via `WithdrawFromGasKeyAction`, which only the account itself can invoke, or via burning it through normal gas spending, which the victim does not necessarily want or control).

This is directly analogous to the reported bug class: an unprivileged third party donates value to manipulate a balance-based trigger/threshold that gates the victim's ability to exit/unsubscribe (here, delete the key/account), without the victim's consent, and at negligible cost to the attacker relative to the harm (fund lock / stuck account state / inability to reclaim storage stake and beneficiary payout on deletion).

### Impact Explanation
- **Denial of intended exit action**: the victim cannot delete a gas key or delete their account while the (attacker-inflated) gas key balance exceeds the 1 NEAR threshold, blocking `DeleteAccountAction`'s beneficiary payout and key cleanup.
- **Unauthorized balance/state mutation**: an attacker can, without any permission, mutate access-key state (`GasKeyInfo.balance`) belonging to a victim account purely by naming that account as `receiver_id` of a `TransferToGasKeyAction`.
- **Fund lock**: locked storage stake / gas-key balance and inability to complete cleanup receipts can trap the account in an undeletable state, which is analogous to the "user can only stand to lose, never unsubscribe" scenario in the source report.

### Likelihood Explanation
High reachability: `TransferToGasKeyAction` is a normal, unprivileged transaction action executable by any account against any `receiver_id`; the target gas key public key is discoverable via the public `ViewAccessKeyList` RPC. No validator or node compromise, no privileged role, and no contract cooperation from the victim is required — a single crafted transaction (or a few, to accumulate past 1 NEAR) suffices.

### Recommendation
- Restrict `TransferToGasKeyAction` (and the underlying `action_transfer_to_gas_key`) so it can only be executed when the predecessor/signer is the account owner (or another explicitly authorized principal), preventing arbitrary third parties from funding another account's gas key.
- Alternatively/additionally, decouple the deletion-blocking threshold from externally-donatable balance, e.g. by capping the burn only on funds contributed by the account itself, or allowing forced/partial burn above the cap instead of hard-failing deletion.

### Proof of Concept
1. Victim `alice.near` has a gas key `pk_gas` with balance 0.9 NEAR (below `MAX_BALANCE_TO_BURN` = 1 NEAR), added via `AddKeyAction`.
2. Attacker `bob.near` submits a transaction: `signer_id: bob.near`, `receiver_id: alice.near`, `actions: [TransferToGasKey { public_key: pk_gas, deposit: 0.2 NEAR }]`.
3. `action_transfer_to_gas_key` executes without checking that `bob.near` is `alice.near`, crediting `pk_gas.balance` to 1.1 NEAR: [6](#0-5) 
4. Alice later submits `DeleteKeyAction { public_key: pk_gas }` or `DeleteAccountAction`. Both fail with `ActionErrorKind::GasKeyBalanceTooHigh` because the gas-key balance now exceeds 1 NEAR: [7](#0-6) [4](#0-3) 
5. Alice is permanently blocked from deleting that key/account until the balance is manually withdrawn below the threshold (only possible via `WithdrawFromGasKeyAction`, which the attacker will not cooperate with, or via burning gas usage the victim doesn't want to perform), demonstrating the griefing/fund-lock impact.

### Citations

**File:** runtime/runtime/src/access_keys.rs (L93-111)
```rust
fn delete_gas_key(
    config: &RuntimeConfig,
    state_update: &mut TrieUpdate,
    account: &mut Account,
    result: &mut ActionResult,
    account_id: &AccountId,
    public_key: &PublicKey,
    access_key: &AccessKey,
    gas_key_info: &GasKeyInfo,
) -> Result<(), RuntimeError> {
    if gas_key_info.balance > GasKeyInfo::MAX_BALANCE_TO_BURN {
        result.result = Err(ActionErrorKind::GasKeyBalanceTooHigh {
            account_id: account_id.clone(),
            public_key: Some(Box::new(public_key.clone())),
            balance: gas_key_info.balance,
        }
        .into());
        return Ok(());
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

**File:** core/primitives-core/src/account.rs (L551-559)
```rust
impl GasKeyInfo {
    /// Maximum gas key balance that can be burned during key or account deletion.
    /// Deletion fails if the (sum of) gas key balance(s) exceeds this threshold.
    pub const MAX_BALANCE_TO_BURN: Balance = Balance::from_near(1);

    pub fn borsh_len() -> usize {
        borsh::object_length(&Self { balance: Balance::from_yoctonear(0), num_nonces: 0 }).unwrap()
    }
}
```

**File:** runtime/runtime/src/actions.rs (L339-348)
```rust
    let gas_key_balance_to_burn = compute_gas_key_balance_sum(state_update, account_id)?;
    if gas_key_balance_to_burn > GasKeyInfo::MAX_BALANCE_TO_BURN {
        result.result = Err(ActionErrorKind::GasKeyBalanceTooHigh {
            account_id: account_id.clone(),
            public_key: None,
            balance: gas_key_balance_to_burn,
        }
        .into());
        return Ok(());
    }
```

**File:** core/primitives/src/errors.rs (L835-841)
```rust
    /// Gas key balance is too high to burn during deletion
    GasKeyBalanceTooHigh {
        account_id: AccountId,
        /// Set for DeleteKey (specific key), None for DeleteAccount (aggregate)
        public_key: Option<Box<PublicKey>>,
        balance: Balance,
    } = 25,
```
