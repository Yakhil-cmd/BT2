### Title
Wrong Variable in Underflow Guard Causes Dead-Code Protection on `newStorageUsed` Subtraction — (`File: fvm/environment/accounts.go`)

### Summary

`setAccountStatusAfterAccountStatusSizeChange` uses `uint64(oldAccountStatusSize)` (the byte-length of the account status register) as the guard for the `newStorageUsed = oldStorageUsed - absChange` subtraction, instead of `oldStorageUsed` (the total storage used by the account). Because `absChange` is derived directly from `oldAccountStatusSize` and can never exceed it, the guard is always `false` — it is dead code. If `oldStorageUsed` is ever less than `absChange` (e.g., due to a state inconsistency from a migration or a prior bug), the subtraction silently wraps to a near-`uint64` maximum, corrupting the account's storage-used counter and effectively bricking the account.

### Finding Description

In `setAccountStatusAfterAccountStatusSizeChange`:

```go
sizeChange := newAccountStatusSize - oldAccountStatusSize   // negative when register shrinks
...
if sizeChange < 0 {
    absChange := uint64(-sizeChange)                        // = oldAccountStatusSize - newAccountStatusSize
    if absChange > uint64(oldAccountStatusSize) {           // BUG: always false
        return fmt.Errorf("storage would be negative for %s", id)
    }
    newStorageUsed = oldStorageUsed - absChange             // unprotected underflow
}
```

`absChange` equals `oldAccountStatusSize − newAccountStatusSize`. Since `newAccountStatusSize ≥ 0`, `absChange ≤ oldAccountStatusSize` by construction, so the guard `absChange > uint64(oldAccountStatusSize)` is **always false** and never fires.

The correct guard — as used in the parallel function `updateRegisterSizeChange` — is `absChange > oldSize` (i.e., `absChange > oldStorageUsed`):

```go
// updateRegisterSizeChange (correct pattern):
if absChange > oldSize {
    return fmt.Errorf("storage would be negative for %s", id)
}
newSize = oldSize - absChange
``` [1](#0-0) [2](#0-1) 

### Impact Explanation

If `oldStorageUsed < absChange` (e.g., the stored storage-used value is stale or was set incorrectly by a migration), the subtraction `newStorageUsed = oldStorageUsed - absChange` wraps around to approximately `2^64 − absChange`. This corrupted value is then written back via `status.SetStorageUsed(newStorageUsed)` and persisted to state. Any subsequent storage-limit check (`usages[i] > capacity`) will always fail for that account, permanently bricking it — no transaction from that account can ever succeed again. [3](#0-2) [4](#0-3) 

### Likelihood Explanation

`setAccountStatusAfterAccountStatusSizeChange` is called during `RevokeAccountPublicKey` and `appendKeyMetadataToAccountStatusRegister` — both reachable by any account owner submitting a transaction. The underflow requires `oldStorageUsed < absChange`, which does not hold under normal invariants (since `oldStorageUsed` includes the account status register itself). However, the guard is provably dead code, so any state inconsistency — from a migration, a prior bug, or an account whose storage-used counter was set to a small value — would trigger the underflow with zero protection. The `AccountUsageMigration` in `cmd/util/ledger/migrations/storage_used_migration.go` demonstrates that storage-used values have historically required correction, making the precondition realistic. [5](#0-4) [6](#0-5) 

### Recommendation

Replace the wrong guard variable to match the pattern used in `updateRegisterSizeChange`:

```go
// Before (wrong — always false):
if absChange > uint64(oldAccountStatusSize) {

// After (correct — mirrors updateRegisterSizeChange):
if absChange > oldStorageUsed {
``` [7](#0-6) 

### Proof of Concept

1. Account `A` has `oldStorageUsed = 10` (e.g., due to a migration that set it incorrectly) and `oldAccountStatusSize = 50`.
2. A transaction calls `RevokeAccountPublicKey`, which calls `setAccountStatusAfterAccountStatusSizeChange`.
3. The new account status register is 10 bytes smaller: `sizeChange = -10`, `absChange = 10`.
4. Guard check: `10 > 50` → **false** (guard never fires).
5. `newStorageUsed = 10 - 10 = 0` — in this case no underflow, but if `oldStorageUsed = 5`: `newStorageUsed = 5 - 10` → wraps to `18446744073709551611`.
6. `status.SetStorageUsed(18446744073709551611)` is persisted.
7. Every subsequent transaction from account `A` fails `usages[i] > capacity` → account is bricked. [8](#0-7)

### Citations

**File:** fvm/environment/accounts.go (L362-385)
```go
func (a *StatefulAccounts) RevokeAccountPublicKey(
	address flow.Address,
	keyIndex uint32,
) error {
	err := a.accountPublicKeyIndexInRange(address, keyIndex)
	if err != nil {
		return err
	}

	if keyIndex == 0 {
		return revokeAccountPublicKey0(a, address)
	}

	status, err := a.getAccountStatus(address)
	if err != nil {
		return err
	}

	err = status.RevokeAccountPublicKey(keyIndex)
	if err != nil {
		return fmt.Errorf("failed to revoke public key at index %d for %s: %w", keyIndex, address, err)
	}

	return a.setAccountStatusAfterAccountStatusSizeChange(address, status)
```

**File:** fvm/environment/accounts.go (L830-838)
```go
	// two paths to avoid casting uint to int
	var newSize uint64
	if sizeChange < 0 {
		absChange := uint64(-sizeChange)
		if absChange > oldSize {
			// should never happen
			return fmt.Errorf("storage would be negative for %s", id)
		}
		newSize = oldSize - absChange
```

**File:** fvm/environment/accounts.go (L1068-1116)
```go
func (a *StatefulAccounts) setAccountStatusAfterAccountStatusSizeChange(
	address flow.Address,
	status *AccountStatus,
) error {
	id := flow.AccountStatusRegisterID(address)

	oldAccountStatusValue, err := a.GetValue(id)
	if err != nil {
		return err
	}
	oldAccountStatusSize := len(oldAccountStatusValue)

	newAccountStatusValue := status.ToBytes()
	newAccountStatusSize := len(newAccountStatusValue)

	sizeChange := newAccountStatusSize - oldAccountStatusSize
	if sizeChange == 0 {
		// Account status register size has not changed.

		// Set account status in underlying state
		return a.txnState.Set(id, newAccountStatusValue)
	}

	oldAccountStatus, err := AccountStatusFromBytes(oldAccountStatusValue)
	if err != nil {
		return err
	}
	oldStorageUsed := oldAccountStatus.StorageUsed()

	// Two paths to avoid casting uint to int
	var newStorageUsed uint64
	if sizeChange < 0 {
		absChange := uint64(-sizeChange)
		if absChange > uint64(oldAccountStatusSize) {
			// should never happen
			return fmt.Errorf("storage would be negative for %s", id)
		}
		newStorageUsed = oldStorageUsed - absChange
	} else {
		absChange := uint64(sizeChange)
		newStorageUsed = oldStorageUsed + absChange
	}

	// Set updated storage used
	status.SetStorageUsed(newStorageUsed)

	// Set account status in underlying state
	return a.txnState.Set(id, status.ToBytes())
}
```

**File:** fvm/transactionStorageLimiter.go (L154-162)
```go
	for i, address := range addresses {
		capacity := environment.StorageMBUFixToBytesUInt(resultArray.Values[i])

		if usages[i] > capacity {
			return errors.NewStorageCapacityExceededError(
				address,
				usages[i],
				capacity)
		}
```

**File:** cmd/util/ledger/migrations/storage_used_migration.go (L149-160)
```go
	if statusSizeDiff < 0 {
		if uint64(-statusSizeDiff) > actualUsed {
			log.Error().
				Str("account", address.HexWithPrefix()).
				Msgf("account storage used would be negative")
			return fmt.Errorf("account storage used would be negative")
		}

		actualUsed = actualUsed - uint64(-statusSizeDiff)
	} else if statusSizeDiff > 0 {
		actualUsed = actualUsed + uint64(statusSizeDiff)
	}
```
