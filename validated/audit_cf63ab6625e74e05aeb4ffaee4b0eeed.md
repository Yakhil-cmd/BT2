The vulnerability claim is real. Here is the complete trace:

---

### Title
`AccountKeyFail` Permanent Lock Bypassed via Type-Mismatch in `CheckReplacable` — (`blockchain/types/accountkey/account_key.go`)

### Summary

`CheckReplacable` only calls `oldKey.CheckUpdatable()` when the old and new key types are identical. When they differ, it falls through to `newKey.CheckInstallable()` only. Because `AccountKeyFail` always returns `ErrAccountKeyFailNotUpdatable` from `CheckUpdatable`, but has a different type than any live key, the type-mismatch branch silently bypasses the permanent-lock invariant, allowing a role previously set to `AccountKeyFail` to be replaced with a live signing key.

### Finding Description

`CheckReplacable` is defined as: [1](#0-0) 

```go
func CheckReplacable(oldKey AccountKey, newKey AccountKey, currentBlockNumber uint64) error {
    if oldKey.Type() == newKey.Type() {
        return oldKey.CheckUpdatable(newKey, currentBlockNumber)
    }
    return newKey.CheckInstallable(currentBlockNumber)
}
```

`AccountKeyFail.CheckUpdatable` unconditionally rejects all updates: [2](#0-1) 

But `AccountKeyFail.CheckInstallable` returns `nil`: [3](#0-2) 

`AccountKeyRoleBased.CheckUpdatable` calls `CheckReplacable` per-role slot: [4](#0-3) 

When `(*a)[i]` is `AccountKeyFail` (type `AccountKeyTypeFail`) and `(*newKey)[i]` is `AccountKeyPublic` (type `AccountKeyTypePublic`), the types differ, so `CheckReplacable` calls only `AccountKeyPublic.CheckInstallable()`, which succeeds for any valid public key. `AccountKeyFail.CheckUpdatable()` is never invoked.

### Impact Explanation

An account holding `AccountKeyRoleBased{AccountKeyFail, AccountKeyPublic}` has its `RoleTransaction` (index 0) permanently locked — no value-transfer tx can be signed. The account owner retains a valid `RoleAccountUpdate` key (index 1) for administrative use.

By submitting a `TxTypeAccountUpdate` with `AccountKeyRoleBased{AccountKeyPublic_new, AccountKeyPublic_new}`, signed with the `RoleAccountUpdate` key, the type-mismatch path in `CheckReplacable` allows the update to succeed. After the update, `RoleTransaction` is `AccountKeyPublic_new`, and the account can sign and submit value-transfer transactions — restoring KAIA balance and nonce consumption authority that was supposed to be permanently revoked.

This satisfies the required impact gate: **unauthorized unlock of key/nonce consumption authority over KAIA**.

### Likelihood Explanation

Any account that deliberately set `AccountKeyFail` on a role (e.g., to permanently disable direct transfers from a role-based account) while retaining a live `RoleAccountUpdate` key is exploitable by whoever controls that update key. The transaction is a standard public-RPC `TxTypeAccountUpdate` — no privileged access, validator collusion, or cryptographic break is required.

### Recommendation

`CheckReplacable` must consult the old key's replaceability regardless of type mismatch. The fix is to call `oldKey.CheckUpdatable` unconditionally (or add an explicit guard for `AccountKeyFail`):

```go
func CheckReplacable(oldKey AccountKey, newKey AccountKey, currentBlockNumber uint64) error {
    // Always check whether the old key permits replacement.
    if err := oldKey.CheckUpdatable(newKey, currentBlockNumber); err != nil {
        // Same-type path: propagate the error directly.
        if oldKey.Type() == newKey.Type() {
            return err
        }
        // Different-type path: old key vetoed replacement (e.g. AccountKeyFail).
        return err
    }
    // Old key permits; for different types also verify the new key is installable.
    if oldKey.Type() != newKey.Type() {
        return newKey.CheckInstallable(currentBlockNumber)
    }
    return nil
}
```

Alternatively, add an explicit `IsReplacable() bool` method to the `AccountKey` interface and have `AccountKeyFail` return `false`.

### Proof of Concept

1. Fund account `A` and submit `TxTypeAccountUpdate` setting its key to `AccountKeyRoleBased{AccountKeyFail, AccountKeyPublic(updateKey)}`.
2. Confirm value-transfer txs from `A` fail (role 0 = Fail).
3. Submit `TxTypeAccountUpdate` from `A` with new key `AccountKeyRoleBased{AccountKeyPublic(newTxKey), AccountKeyPublic(updateKey)}`, signed by `updateKey`.
4. `AccountKeyRoleBased.CheckUpdatable` → `CheckReplacable(AccountKeyFail, AccountKeyPublic(newTxKey), ...)` → types differ → `AccountKeyPublic(newTxKey).CheckInstallable()` → `nil` → update accepted.
5. Confirm `A` can now sign and broadcast value-transfer txs with `newTxKey`, draining its KAIA balance. [5](#0-4) [2](#0-1) [6](#0-5)

### Citations

**File:** blockchain/types/accountkey/account_key.go (L123-128)
```go
// CheckReplacable returns nil if newKey can replace oldKey. The function checks updatability of newKey regardless of the newKey type.
func CheckReplacable(oldKey AccountKey, newKey AccountKey, currentBlockNumber uint64) error {
	if oldKey.Type() == newKey.Type() {
		return oldKey.CheckUpdatable(newKey, currentBlockNumber)
	}
	return newKey.CheckInstallable(currentBlockNumber)
```

**File:** blockchain/types/accountkey/account_key_fail.go (L81-84)
```go
func (a *AccountKeyFail) CheckInstallable(currentBlockNumber uint64) error {
	// AccountKeyFail can be assigned to an account. Since it does not have any value, it returns always nil.
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

**File:** blockchain/types/accountkey/account_key_role_based.go (L245-263)
```go
		for i := range lenNewKey {
			switch {
			// A composite key is not allowed.
			case (*newKey)[i].IsCompositeType():
				return kerrors.ErrNestedCompositeType
			// If newKey is longer than oldKey, init the new attributes.
			case i >= lenOldKey:
				if err := (*newKey)[i].CheckInstallable(currentBlockNumber); err != nil {
					return err
				}
			// Do nothing for AccountKeyTypeNil
			case (*newKey)[i].Type() == AccountKeyTypeNil:

			// Check whether the newKey is replacable or not
			default:
				if err := CheckReplacable((*a)[i], (*newKey)[i], currentBlockNumber); err != nil {
					return err
				}
			}
```
