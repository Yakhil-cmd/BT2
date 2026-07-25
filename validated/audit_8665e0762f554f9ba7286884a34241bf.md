The vulnerability is real. Let me trace the exact execution path to confirm.

**Execution trace:**

1. Account state: `AccountKeyRoleBased{AccountKeyFail, AccountKeyPublic}` (role 0 = Fail, role 1 = AccountUpdate key)

2. Attacker (controlling role 1) submits `TxTypeAccountUpdate` with `AccountKeyRoleBased{AccountKeyPublic_new, AccountKeyPublic_new}`

3. `TxInternalDataAccountUpdate.Validate()` calls `accountkey.CheckReplacable(oldKey, t.Key, ...)`: [1](#0-0) 

4. Both outer keys are `AccountKeyTypeRoleBased`, so `CheckReplacable` calls `oldKey.CheckUpdatable(newKey, ...)`: [2](#0-1) 

5. Inside `AccountKeyRoleBased.CheckUpdatable`, for `i=0`: `(*newKey)[0]` is `AccountKeyPublic` (not nil, not composite, `i < lenOldKey`), so it falls into the `default` case and calls `CheckReplacable((*a)[0], (*newKey)[0], ...)` = `CheckReplacable(AccountKeyFail, AccountKeyPublic_new, ...)`: [3](#0-2) 

6. **The bypass**: In `CheckReplacable`, `AccountKeyTypeFail != AccountKeyTypePublic`, so it calls `newKey.CheckInstallable()` — **never calling `AccountKeyFail.CheckUpdatable()`**: [2](#0-1) 

7. `AccountKeyPublic.CheckInstallable()` returns `nil` for a valid curve point. The update succeeds. [4](#0-3) 

8. `AccountKeyFail.CheckUpdatable()` — which unconditionally returns `ErrAccountKeyFailNotUpdatable` — is never reached: [5](#0-4) 

9. `AccountKeyRoleBased.Update()` writes `AccountKeyPublic_new` into role 0, overwriting `AccountKeyFail` in state: [6](#0-5) 

---

### Title
`CheckReplacable` type-mismatch path bypasses `AccountKeyFail` permanent-lock invariant inside `AccountKeyRoleBased` — (`blockchain/types/accountkey/account_key.go`)

### Summary
`CheckReplacable` only calls `oldKey.CheckUpdatable()` when `oldKey.Type() == newKey.Type()`. When types differ, it calls only `newKey.CheckInstallable()`. This means an `AccountKeyFail` slot inside an `AccountKeyRoleBased` can be replaced by any valid key of a different type, violating the documented invariant that `AccountKeyFail` is permanently non-updatable.

### Finding Description
`AccountKeyFail.CheckUpdatable` unconditionally returns `ErrAccountKeyFailNotUpdatable` to enforce that a fail-locked role can never be replaced. However, `AccountKeyRoleBased.CheckUpdatable` delegates per-slot validation to the top-level `CheckReplacable`:

```go
// account_key.go:124-129
func CheckReplacable(oldKey AccountKey, newKey AccountKey, currentBlockNumber uint64) error {
    if oldKey.Type() == newKey.Type() {
        return oldKey.CheckUpdatable(newKey, currentBlockNumber)
    }
    return newKey.CheckInstallable(currentBlockNumber)  // ← bypasses oldKey entirely
}
```

When `oldKey` is `AccountKeyFail` (type 3) and `newKey` is `AccountKeyPublic` (type 2), the types differ, so `oldKey.CheckUpdatable()` is skipped. `AccountKeyPublic.CheckInstallable()` returns `nil` for any valid EC point, so the update is accepted and committed to state.

### Impact Explanation
An account holding `AccountKeyRoleBased{AccountKeyFail, AccountKeyPublic}` has its `RoleTransaction` (role 0) permanently locked — it cannot sign value-transfer transactions. The holder of the `RoleAccountUpdate` key (role 1) can submit a `TxTypeAccountUpdate` replacing role 0 with a live `AccountKeyPublic`, restoring full KAIA balance and nonce consumption authority to a role that was supposed to be irrevocably locked. This constitutes unauthorized key/nonce consumption authority restoration affecting KAIA.

### Likelihood Explanation
The attack requires controlling the `RoleAccountUpdate` key of the target account. Any account that was deliberately configured with `AccountKeyFail` at `RoleTransaction` while retaining a live `RoleAccountUpdate` key is exploitable by whoever holds that update key. This is a permissionless on-chain transaction requiring no privileged access beyond the update key itself.

### Recommendation
In `CheckReplacable`, when `oldKey` and `newKey` types differ, also check that the old key permits replacement. Specifically, add a guard:

```go
func CheckReplacable(oldKey AccountKey, newKey AccountKey, currentBlockNumber uint64) error {
    if oldKey.Type() == newKey.Type() {
        return oldKey.CheckUpdatable(newKey, currentBlockNumber)
    }
    // Even when types differ, the old key must permit being replaced.
    if err := oldKey.CheckUpdatable(newKey, currentBlockNumber); err != nil {
        // AccountKeyFail and others that block all updates will reject here.
        // For keys that only reject same-type updates (ErrDifferentAccountKeyType),
        // allow the cross-type install check to proceed.
        if err != kerrors.ErrDifferentAccountKeyType {
            return err
        }
    }
    return newKey.CheckInstallable(currentBlockNumber)
}
```

Alternatively, `AccountKeyFail` could implement a sentinel interface or flag that `CheckReplacable` checks before taking the type-mismatch path.

### Proof of Concept
```go
// Setup: account with AccountKeyRoleBased{AccountKeyFail, AccountKeyPublic(updateKey)}
oldKey := accountkey.NewAccountKeyRoleBasedWithValues(accountkey.AccountKeyRoleBased{
    accountkey.NewAccountKeyFail(),                              // role 0: locked
    accountkey.NewAccountKeyPublicWithValue(&updateKey.PublicKey), // role 1: update key
})
// stateDB.SetKey(addr, oldKey)

// Attack: submit TxTypeAccountUpdate signed by updateKey
newKey := accountkey.NewAccountKeyRoleBasedWithValues(accountkey.AccountKeyRoleBased{
    accountkey.NewAccountKeyPublicWithValue(&attackerKey.PublicKey), // replaces Fail
    accountkey.NewAccountKeyPublicWithValue(&updateKey.PublicKey),
})

// CheckReplacable(oldKey, newKey, ...) returns nil — update succeeds
err := accountkey.CheckReplacable(oldKey, newKey, 0)
// err == nil  ← BUG: should be ErrAccountKeyFailNotUpdatable

// Account can now sign value-transfer txs with attackerKey
```

### Citations

**File:** blockchain/types/tx_internal_data_account_update.go (L292-296)
```go
func (t *TxInternalDataAccountUpdate) Validate(stateDB StateDB, currentBlockNumber uint64, onlyMutableChecks bool) error {
	oldKey := stateDB.GetKey(t.From)
	if err := accountkey.CheckReplacable(oldKey, t.Key, currentBlockNumber); err != nil {
		return err
	}
```

**File:** blockchain/types/accountkey/account_key.go (L124-129)
```go
func CheckReplacable(oldKey AccountKey, newKey AccountKey, currentBlockNumber uint64) error {
	if oldKey.Type() == newKey.Type() {
		return oldKey.CheckUpdatable(newKey, currentBlockNumber)
	}
	return newKey.CheckInstallable(currentBlockNumber)
}
```

**File:** blockchain/types/accountkey/account_key_role_based.go (L259-262)
```go
			default:
				if err := CheckReplacable((*a)[i], (*newKey)[i], currentBlockNumber); err != nil {
					return err
				}
```

**File:** blockchain/types/accountkey/account_key_role_based.go (L271-287)
```go
func (a *AccountKeyRoleBased) Update(newKey AccountKey, currentBlockNumber uint64) error {
	if err := a.CheckUpdatable(newKey, currentBlockNumber); err != nil {
		return err
	}
	newRoleKey, _ := newKey.(*AccountKeyRoleBased)
	lenNewKey := len(*newRoleKey)
	lenOldKey := len(*a)
	if lenOldKey < lenNewKey {
		*a = append(*a, (*newRoleKey)[lenOldKey:]...)
	}
	for i := range lenNewKey {
		if (*newRoleKey)[i].Type() == AccountKeyTypeNil {
			continue
		}
		(*a)[i] = (*newRoleKey)[i]
	}
	return nil
```

**File:** blockchain/types/accountkey/account_key_public.go (L95-101)
```go
func (a *AccountKeyPublic) CheckInstallable(currentBlockNumber uint64) error {
	// If the point is not on the curve, return an error.
	if a.IsOnCurve(a.X, a.Y) == false {
		return kerrors.ErrNotOnCurve
	}
	return nil
}
```

**File:** blockchain/types/accountkey/account_key_fail.go (L86-89)
```go
func (a *AccountKeyFail) CheckUpdatable(newKey AccountKey, currentBlockNumber uint64) error {
	// AccountKeyFail cannot be updated with any key, hence it returns always an error.
	return kerrors.ErrAccountKeyFailNotUpdatable
}
```
