## Analog Found

The Badger-Finance bug class — an unprivileged actor depositing "dust" into a victim's locked balance to trip a hard threshold check that blocks the victim's own subsequent withdrawal/deletion action — has a direct analog in nearcore's gas-key subsystem.

### Title
Unprivileged `TransferToGasKey` action lets any account grief a victim's `DeleteKey`/`DeleteAccount` by pushing gas-key balance over the burn threshold - (File: `runtime/runtime/src/actions.rs`)

### Summary
`check_actor_permissions` explicitly exempts `Action::TransferToGasKey` from the actor-identity check that is otherwise mandatory for administrative/self-actions (`Stake`, `AddKey`, `DeleteKey`, `WithdrawFromGasKey`, etc.), meaning *any* account can fund *any other* account's gas key with an arbitrary deposit. Gas-key deletion (`delete_gas_key`) and account deletion (`action_delete_account`) both reject the operation if the gas key balance (or the sum of all gas key balances) exceeds `GasKeyInfo::MAX_BALANCE_TO_BURN` (1 NEAR). An attacker can therefore top up a victim's gas key just above this threshold to block the victim's `DeleteKey`/`DeleteAccount` transaction, mirroring the AuraLocker "dust lock" DoS.

### Finding Description
`check_actor_permissions` groups actions into two classes: administrative actions requiring `actor_id == account_id` (`DeployContract`, `Stake`, `AddKey`, `DeleteKey`, `WithdrawFromGasKey`, `DeleteAccount`), and unrestricted actions (`CreateAccount`, `FunctionCall`, `Transfer`, `TransferToGasKey`). [1](#0-0) 

`TransferToGasKey` only requires that the target gas key exists on the account; it does not check that the caller is the account owner: [2](#0-1) 

The delete-key path enforces a hard cap on how much gas-key balance may be burned: [3](#0-2) 

`GasKeyInfo::MAX_BALANCE_TO_BURN` is a fixed constant of 1 NEAR: [4](#0-3) 

`action_delete_account` performs the analogous aggregate check across *all* gas keys on the account before allowing deletion: [5](#0-4) 

Because `TransferToGasKey` bypasses the actor-permission check, any unprivileged account can send this action against a victim's account/gas key (analogous to `AuraLocker.lock(strategy, amount)` allowing anyone to lock funds on behalf of an arbitrary address in the Badger report) and push the balance above `MAX_BALANCE_TO_BURN`, causing the victim's own `DeleteKey` or `DeleteAccount` transaction to fail with `GasKeyBalanceTooHigh`.

### Impact Explanation
This is a griefing/DoS vector reachable from an ordinary, unprivileged transaction: an attacker can prevent a victim from deleting a gas key or their account, e.g. during key rotation, account cleanup, or contract migration flows that rely on `DeleteKey`/`DeleteAccount` succeeding. It matches the "no-impact-if-mitigated" caveat in the reference report — the victim can withdraw the gas key balance via `WithdrawFromGasKey` (a privileged, actor-restricted action) atomically together with `DeleteKey`/`DeleteAccount` in the same transaction to avoid the front-run window, similar to Badger's `manualSendAuraToVault` escape hatch. However, any code path that issues `DeleteKey`/`DeleteAccount` as a standalone transaction (without first draining and combining the withdrawal in the same receipt) is vulnerable to this front-running DoS, and repeated attacks force the victim to always withdraw-then-delete atomically or be blocked indefinitely.

### Likelihood Explanation
Likelihood is moderate: the attack requires the attacker to observe the victim's pending `DeleteKey`/`DeleteAccount` transaction (or simply pre-emptively fund any account they wish to grief) and to spend up to just under 1 NEAR in `deposit` to cross the threshold — a modest but real cost, and those funds are not necessarily lost to the attacker forever unless the account is eventually deleted (at which point the token is burned per `tokens_burnt` accounting), similar to the "dust" cost of the original Badger PoC. No special privileges or validator/node compromise are required — it is purely a transaction constructed by any account against `TransferToGasKey`.

### Recommendation
Either (a) require `actor_id == account_id` for `TransferToGasKey` (matching `WithdrawFromGasKey`), so third parties cannot top up another account's gas key without permission, or (b) if third-party funding of gas keys is an intentional feature, ensure `DeleteKey`/`DeleteAccount` do not hard-fail on excess balance but instead auto-burn/refund the excess (or refund to `beneficiary_id`) rather than blocking deletion outright, removing the DoS vector entirely.

### Proof of Concept
1. Victim account `V` has an existing `GasKeyFullAccess` gas key `pk` with balance close to but below 1 NEAR (e.g. 0.99 NEAR), intending to later call `DeleteKey(pk)` or `DeleteAccount`.
2. Attacker `A` (any unprivileged account, no special permission on `V`) submits a transaction to `V` with a single `Action::TransferToGasKey { public_key: pk, deposit: 0.02 NEAR }`. Because `check_actor_permissions` does not restrict `TransferToGasKey`, this succeeds even though `A != V`. [6](#0-5) 
3. `pk`'s gas key balance is now 1.01 NEAR, exceeding `GasKeyInfo::MAX_BALANCE_TO_BURN`.
4. `V` submits `DeleteKey(pk)` (or `DeleteAccount`); the receipt fails with `ActionErrorKind::GasKeyBalanceTooHigh`, as exercised by the existing test `test_delete_gas_key_balance_too_high` / `test_delete_account_gas_key_balance_too_high`. [7](#0-6) [8](#0-7) 
5. `V`'s deletion is blocked until `V` first issues a privileged `WithdrawFromGasKey` (which `A` cannot prevent from being re-griefed by repeating step 2 unless `V` combines withdraw+delete atomically in one transaction).

### Citations

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

**File:** runtime/runtime/src/actions.rs (L711-757)
```rust
pub(crate) fn check_actor_permissions(
    action: &Action,
    account: &Option<Account>,
    actor_id: &AccountId,
    account_id: &AccountId,
) -> Result<(), ActionError> {
    match action {
        Action::DeployContract(_)
        | Action::Stake(_)
        | Action::AddKey(_)
        | Action::DeleteKey(_)
        | Action::DeployGlobalContract(_)
        | Action::UseGlobalContract(_)
        | Action::WithdrawFromGasKey(_) => {
            if actor_id != account_id {
                return Err(ActionErrorKind::ActorNoPermission {
                    account_id: account_id.clone(),
                    actor_id: actor_id.clone(),
                }
                .into());
            }
        }
        Action::DeleteAccount(_) => {
            if actor_id != account_id {
                return Err(ActionErrorKind::ActorNoPermission {
                    account_id: account_id.clone(),
                    actor_id: actor_id.clone(),
                }
                .into());
            }
            let account = account.as_ref().unwrap();
            if !account.locked().is_zero() {
                return Err(ActionErrorKind::DeleteAccountStaking {
                    account_id: account_id.clone(),
                }
                .into());
            }
        }
        Action::CreateAccount(_)
        | Action::FunctionCall(_)
        | Action::Transfer(_)
        | Action::TransferToGasKey(_) => (),
        Action::Delegate(_) | Action::DelegateV2(_) => (),
        Action::DeterministicStateInit(_) => (),
    };
    Ok(())
}
```

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

**File:** runtime/runtime/src/access_keys.rs (L1043-1081)
```rust
    #[test]
    fn test_delete_gas_key_balance_too_high() {
        let (account_id, public_key, access_key) = test_account_keys();
        let mut state_update = setup_account(&account_id, &public_key, &access_key);
        let mut account = get_account(&state_update, &account_id).unwrap().unwrap();

        let gas_key_public_key =
            InMemorySigner::from_seed(account_id.clone(), KeyType::ED25519, "gas_key").public_key();
        add_gas_key_to_account(&mut state_update, &mut account, &account_id, &gas_key_public_key);

        let deposit_amount = Balance::from_near(1).checked_add(Balance::from_yoctonear(1)).unwrap();
        transfer_to_gas_key(&mut state_update, &account_id, &gas_key_public_key, deposit_amount);

        let mut result = ActionResult::default();
        let action = DeleteKeyAction { public_key: gas_key_public_key.clone() };
        action_delete_key(
            &RuntimeConfig::test(),
            &mut state_update,
            &mut account,
            &mut result,
            &account_id,
            &action,
        )
        .unwrap();
        assert_eq!(
            result.result,
            Err(ActionErrorKind::GasKeyBalanceTooHigh {
                account_id: account_id.clone(),
                public_key: Some(Box::new(gas_key_public_key.clone())),
                balance: deposit_amount,
            }
            .into())
        );
        assert_eq!(result.tokens_burnt, Balance::ZERO);

        // Key should still exist
        let stored_key = get_access_key(&state_update, &account_id, &gas_key_public_key).unwrap();
        assert!(stored_key.is_some());
    }
```

**File:** runtime/runtime/src/access_keys.rs (L1115-1157)
```rust
    #[test]
    fn test_delete_account_gas_key_balance_too_high() {
        let (account_id, public_key, access_key) = test_account_keys();
        let public_keys: Vec<PublicKey> = (0..3)
            .map(|i| PublicKey::from_seed(KeyType::ED25519, &format!("gas_key_{i}")))
            .collect();
        let mut state_update = setup_account(&account_id, &public_key, &access_key);
        let mut account = get_account(&state_update, &account_id).unwrap().unwrap();
        for public_key in &public_keys {
            add_gas_key_to_account(&mut state_update, &mut account, &account_id, public_key);
        }

        // Fund gas keys so total exceeds 1 NEAR
        let deposit_amounts = [
            Balance::from_millinear(400),
            Balance::from_millinear(400),
            Balance::from_millinear(201),
        ];
        for (pk, amount) in public_keys.iter().zip(deposit_amounts.iter()) {
            transfer_to_gas_key(&mut state_update, &account_id, pk, *amount);
        }
        state_update.commit(StateChangeCause::InitialState);

        let action_result = test_delete_account(
            &account_id,
            AccountContract::from_local_code_hash(CryptoHash::default()),
            100,
            PROTOCOL_VERSION,
            &mut state_update,
        );
        let expected_total =
            deposit_amounts.iter().fold(Balance::ZERO, |acc, x| acc.checked_add(*x).unwrap());
        assert_eq!(
            action_result.result,
            Err(ActionErrorKind::GasKeyBalanceTooHigh {
                account_id: account_id.clone(),
                public_key: None,
                balance: expected_total,
            }
            .into())
        );
        assert_eq!(action_result.tokens_burnt, Balance::ZERO);
    }
```

**File:** core/primitives-core/src/account.rs (L551-558)
```rust
impl GasKeyInfo {
    /// Maximum gas key balance that can be burned during key or account deletion.
    /// Deletion fails if the (sum of) gas key balance(s) exceeds this threshold.
    pub const MAX_BALANCE_TO_BURN: Balance = Balance::from_near(1);

    pub fn borsh_len() -> usize {
        borsh::object_length(&Self { balance: Balance::from_yoctonear(0), num_nonces: 0 }).unwrap()
    }
```
