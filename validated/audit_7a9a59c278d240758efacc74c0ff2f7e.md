I have all the information needed. Let me trace the exact code path.

The critical function is `action_transfer_or_implicit_account_creation` in `lib.rs`: [1](#0-0) 

The logic is:
1. `is_gas_refund = is_refund && signer_id == receiver_id` — true for any `Receipt::new_gas_refund`
2. Call `try_refund_gas_key_balance` — returns `false` if key exists but is **not** a gas key
3. Fall through to `action_transfer(account, deposit)` — credits account balance
4. Then unconditionally call `try_refund_allowance` — inflates `FunctionCallPermission.allowance` via `saturating_add` [2](#0-1) [3](#0-2) 

The scenario the question describes is real and the code path is concrete:

- Original tx signed with gas key K → `gas_key_info.balance` debited
- Owner deletes gas key K, adds `FunctionCallPermission` key with same public key K and `allowance = Some(X)`
- Gas refund receipt arrives (`signer_public_key = K`)
- `try_refund_gas_key_balance(K)` → key exists, `gas_key_info_mut()` returns `None` → returns `false`
- `action_transfer` → account balance credited ✓ (correct fallback)
- `try_refund_allowance(K)` → key exists, is `FunctionCallPermission`, allowance is `Some(X)` → `allowance = X.saturating_add(refund)` ✗

The allowance was **never debited** for this transaction (the gas key balance was debited, not any FunctionCallPermission allowance). The refund inflates the allowance without a corresponding prior debit.

The documentation at `docs/RuntimeSpec/Refunds.md` lines 57–63 explicitly describes the "best effort" allowance refund as applying to the case where the original key was a `FunctionCallPermission` key. The code does not distinguish between "key was originally a gas key, now replaced" vs "key was always a FunctionCallPermission key." [4](#0-3) 

---

### Title
Gas Refund to Replaced FunctionCallPermission Key Inflates Allowance Without Prior Debit — (`runtime/runtime/src/lib.rs`)

### Summary
When a gas key is replaced with a `FunctionCallPermission` key (same public key) between transaction submission and gas refund arrival, `action_transfer_or_implicit_account_creation` credits the account balance (correct fallback) **and** additionally inflates the `FunctionCallPermission` key's allowance via `try_refund_allowance`, even though that allowance was never debited for the original gas key transaction.

### Finding Description
In `runtime/runtime/src/lib.rs` at `action_transfer_or_implicit_account_creation`: [1](#0-0) 

The `try_refund_allowance` call at line 2857 is guarded only by `is_gas_refund`, not by whether the key at `signer_public_key` was **originally** a gas key. When `try_refund_gas_key_balance` returns `false` because the key is now a `FunctionCallPermission` key (not because it is absent), the code falls through to both `action_transfer` and `try_refund_allowance`. The allowance `saturating_add` in `try_refund_allowance`: [5](#0-4) 

increases the allowance by the full refund amount with no corresponding prior debit of that allowance.

### Impact Explanation
The exact corrupted value is `FunctionCallPermission.allowance`, inflated by the gas refund amount (up to the full unused gas converted to tokens). The account balance is also correctly credited, so no funds are created from nothing — but the `FunctionCallPermission` key gains spending authority (`allowance`) beyond what the account owner set, without any corresponding debit. This violates the invariant that allowance is only refunded when it was previously charged.

Impact is scoped to the attacker's own account: they cannot steal funds from other accounts. However, they can bypass the allowance cap they (or a delegating party) set on a `FunctionCallPermission` key by cycling through gas key → FunctionCallPermission key replacement timed around gas refunds.

### Likelihood Explanation
Requires the account owner to: (1) hold a gas key, (2) submit a transaction with it, (3) replace the gas key with a `FunctionCallPermission` key at the same public key before the refund receipt is applied. All three steps are normal, unprivileged user operations. The gas key feature is gated behind `ProtocolFeature::GasKeys`, so this is not yet exploitable on mainnet, but will be once the feature activates.

### Recommendation
`try_refund_allowance` should only be called when the key at `signer_public_key` was **not** found to be a gas key because it is a `FunctionCallPermission` key that was always a `FunctionCallPermission` key — i.e., the original transaction was signed with a `FunctionCallPermission` key. One concrete fix: have `try_refund_gas_key_balance` return a tri-state (`KeyNotFound` / `NotAGasKey` / `Credited`) and only call `try_refund_allowance` on `KeyNotFound`, not on `NotAGasKey`.

### Proof of Concept
```rust
// 1. Setup: alice has a gas key with balance
let gas_key_signer = ...; // gas key
// 2. Apply gas refund receipt targeting the gas key public key
let refund = Receipt::new_gas_refund(&alice_account(), refund_amount, gas_key_signer.public_key());
// 3. Before applying refund: delete gas key, add FunctionCallPermission key with same pubkey
//    and allowance = Some(small_amount)
// 4. Apply the refund receipt
// 5. Assert: FunctionCallPermission allowance == small_amount (NOT small_amount + refund_amount)
//    This assertion FAILS, demonstrating the bug.
``` [6](#0-5) 

The existing test `test_gas_refund_to_gas_key` covers the happy path but not the key-replacement scenario. A new test following the proof-of-concept above would reproduce the allowance inflation.

### Citations

**File:** runtime/runtime/src/lib.rs (L2843-2864)
```rust
        let is_gas_refund = is_refund && action_receipt.signer_id() == receipt.receiver_id();
        // For gas refunds, try to refund to the gas key first. If the signer key is a gas key,
        // the refund goes to the gas key balance and we skip crediting the account balance.
        if is_gas_refund
            && try_refund_gas_key_balance(
                state_update,
                receipt.receiver_id(),
                &action_receipt.signer_public_key(),
                deposit,
            )?
        {
            return Ok(());
        }
        action_transfer(account, deposit)?;
        if is_gas_refund {
            try_refund_allowance(
                state_update,
                receipt.receiver_id(),
                &action_receipt.signer_public_key(),
                deposit,
            )?;
        }
```

**File:** runtime/runtime/src/actions.rs (L100-116)
```rust
pub(crate) fn try_refund_gas_key_balance(
    state_update: &mut TrieUpdate,
    account_id: &AccountId,
    public_key: &PublicKey,
    deposit: Balance,
) -> Result<bool, StorageError> {
    let Some(mut access_key) = get_access_key(state_update, account_id, public_key)? else {
        return Ok(false);
    };
    let Some(gas_key_info) = access_key.gas_key_info_mut() else {
        return Ok(false);
    };
    gas_key_info.balance = gas_key_info.balance.checked_add(deposit).ok_or_else(|| {
        StorageError::StorageInconsistentState("gas key balance integer overflow".to_string())
    })?;
    set_access_key(state_update, account_id.clone(), public_key.clone(), &access_key);
    Ok(true)
```

**File:** runtime/runtime/src/actions.rs (L119-143)
```rust
pub(crate) fn try_refund_allowance(
    state_update: &mut TrieUpdate,
    account_id: &AccountId,
    public_key: &PublicKey,
    deposit: Balance,
) -> Result<(), StorageError> {
    if let Some(mut access_key) = get_access_key(state_update, account_id, public_key)? {
        let mut updated = false;
        if let AccessKeyPermission::FunctionCall(function_call_permission) =
            &mut access_key.permission
        {
            if let Some(allowance) = function_call_permission.allowance.as_mut() {
                let new_allowance = allowance.saturating_add(deposit);
                if new_allowance > *allowance {
                    *allowance = new_allowance;
                    updated = true;
                }
            }
        }
        if updated {
            set_access_key(state_update, account_id.clone(), public_key.clone(), &access_key);
        }
    }
    Ok(())
}
```

**File:** docs/RuntimeSpec/Refunds.md (L57-63)
```markdown
Note, that it's not always possible to refund the allowance, because the access key can be deleted between the moment when the transaction was
issued and when the gas refund arrived. In this case we use the best effort to refund the allowance. It means:

- the access key on the `signer_id` account with the public key `signer_public_key` should exist
- the access key permission should be `FunctionCallPermission`
- the allowance should be set to `Some` limited value, instead of unlimited allowance (`None`)
- the runtime uses saturating add to increase the allowance, to avoid overflows
```

**File:** runtime/runtime/src/tests/apply.rs (L3999-4050)
```rust
fn test_gas_refund_to_gas_key() {
    let initial_balance = Balance::from_near(1_000_000);
    let gas_key_balance = Balance::from_millinear(10);
    let GasKeyTestSetup {
        runtime,
        tries,
        root,
        mut apply_state,
        epoch_info_provider,
        gas_key_signer,
        shard_uid,
    } = setup_gas_key_test(
        alice_account(),
        vec![alice_account()],
        initial_balance,
        1,
        gas_key_balance,
    );

    // Create a gas refund receipt targeting alice's gas key
    let refund_amount = Balance::from_millinear(1);
    let gas_refund =
        Receipt::new_gas_refund(&alice_account(), refund_amount, gas_key_signer.public_key());

    // Apply the refund receipt
    let apply_result = runtime
        .apply(
            tries.get_trie_for_shard(shard_uid, root),
            &None,
            &apply_state,
            &[gas_refund],
            SignedValidPeriodTransactions::empty(),
            &epoch_info_provider,
            Default::default(),
        )
        .unwrap();

    let root = commit_apply_result(&apply_result, &mut apply_state, &tries, shard_uid);
    let state = tries.new_trie_update(shard_uid, root);

    // Gas key balance should increase by refund amount
    let access_key =
        get_access_key(&state, &alice_account(), &gas_key_signer.public_key()).unwrap().unwrap();
    assert_eq!(
        access_key.gas_key_info().unwrap().balance,
        gas_key_balance.checked_add(refund_amount).unwrap()
    );

    // Account balance should NOT change
    let alice = get_account(&state, &alice_account()).unwrap().unwrap();
    assert_eq!(alice.amount(), initial_balance);
}
```
