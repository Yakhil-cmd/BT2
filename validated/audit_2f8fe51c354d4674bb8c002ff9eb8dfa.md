The `Update` function behavior is the key. Let me verify the `Validate` path for fee payer authorization to confirm the full exploit chain.

The exploit path is fully traceable. Here is the complete analysis:

---

### Title
Irrevocable RoleFeePayer Key After Partial Role-Based Key Update — (`blockchain/types/accountkey/account_key_role_based.go`)

### Summary

`AccountKeyRoleBased.Update` never truncates the underlying slice when the new key has fewer elements than the old key. An account owner who updates from a 3-element role-based key to a 1-element role-based key intending to remove `RoleFeePayer` leaves the old `RoleFeePayer` key permanently active in account state. Any party who previously held that private key retains the ability to authorize fee-delegated transactions against the victim account indefinitely.

### Finding Description

`AccountKeyRoleBased` is a Go slice of `AccountKey`, indexed by role ordinal (`RoleTransaction=0`, `RoleAccountUpdate=1`, `RoleFeePayer=2`).

The `Update` function:

```go
func (a *AccountKeyRoleBased) Update(newKey AccountKey, currentBlockNumber uint64) error {
    ...
    lenNewKey := len(*newRoleKey)   // e.g. 1
    lenOldKey := len(*a)            // e.g. 3
    if lenOldKey < lenNewKey {      // false — no append
        *a = append(*a, (*newRoleKey)[lenOldKey:]...)
    }
    for i := range lenNewKey {      // only i=0
        if (*newRoleKey)[i].Type() == AccountKeyTypeNil {
            continue
        }
        (*a)[i] = (*newRoleKey)[i]  // only (*a)[0] is replaced
    }
    return nil
}
``` [1](#0-0) 

When `lenNewKey (1) < lenOldKey (3)`, the slice is **never truncated**. After the update, `*a` still has length 3: `[K_new, old_K1, old_K2]`. The old `RoleFeePayer` key at index 2 is never cleared.

The `Validate` function dispatches by role index:

```go
func (a *AccountKeyRoleBased) Validate(..., r RoleType, ...) bool {
    if len(*a) > int(r) {
        return (*a)[r].Validate(...)   // uses (*a)[2] = old K2
    }
    return a.getDefaultKey().Validate(...)  // fallback — never reached
}
``` [2](#0-1) 

Because `len(*a)` is still 3, the fallback to `RoleTransaction` (the intended post-update behavior documented in the type comment) is **never triggered**. [3](#0-2) 

Fee payer validation calls `ValidateAccountKey` with `RoleFeePayer`, which routes through `Validate` above and accepts the stale old key: [4](#0-3) 

### Impact Explanation

An attacker who previously held the `RoleFeePayer` private key (e.g., a fee-payer service the account owner contracted) can continue to sign fee-delegated transactions naming the victim account as fee payer. Every such transaction causes the victim's KAIA balance to be charged for gas. The account owner has no on-chain mechanism to revoke this: updating to a 1-element role-based key silently fails to remove the old `RoleFeePayer` entry. This constitutes an **unauthorized fee charge against KAIA**, which is an in-scope impact.

### Likelihood Explanation

The scenario requires the attacker to have previously held the `RoleFeePayer` private key — a realistic precondition for any account that ever used a third-party fee-payer service. The update transaction itself is a normal, permissionless `TxTypeAccountUpdate` signed by the account owner. No privileged access, validator collusion, or cryptographic break is required. The bug is triggered by the ordinary account-update flow.

### Recommendation

In `AccountKeyRoleBased.Update`, truncate the slice to `lenNewKey` after the element-copy loop when `lenNewKey < lenOldKey`:

```go
if lenOldKey > lenNewKey {
    *a = (*a)[:lenNewKey]
}
```

This ensures that roles not present in the new key are removed, matching the documented invariant that absent roles fall back to `RoleTransaction`.

### Proof of Concept

1. Create account `V` with a 3-element `AccountKeyRoleBased`: `[K_tx, K_update, K_feepayer]`. Share `K_feepayer` private key with attacker `A`.
2. `V` submits `TxTypeAccountUpdate` with a 1-element `AccountKeyRoleBased`: `[K_tx_new]`, signed with `K_update`. Transaction succeeds.
3. Inspect `V`'s account key in state: `len(*a)` is still 3; `(*a)[2]` is still `K_feepayer`.
4. `A` constructs a fee-delegated value transfer (`TxTypeFeeDelegatedValueTransfer`) naming `V` as fee payer, signs the fee-payer field with `K_feepayer`.
5. Submit to public RPC. `ValidateFeePayer` calls `Validate(RoleFeePayer)` → `len(*a)=3 > 2` → uses `(*a)[2]=K_feepayer` → validation passes.
6. `V`'s KAIA balance is debited for gas. `A` repeats indefinitely.

### Citations

**File:** blockchain/types/accountkey/account_key_role_based.go (L47-54)
```go
// AccountKeyRoleBased represents a role-based key.
// The roles are defined like below:
// RoleTransaction   - this key is used to verify transactions transferring values.
// RoleAccountUpdate - this key is used to update keys in the account when using TxTypeAccountUpdate.
// RoleFeePayer      - this key is used to pay tx fee when using fee-delegated transactions. If an account has a key of this role and wants to pay tx fee, fee-delegated transactions should be signed by this key.
//
// If RoleAccountUpdate or RoleFeePayer is not set, RoleTransaction will be used instead by default.
type AccountKeyRoleBased []AccountKey
```

**File:** blockchain/types/accountkey/account_key_role_based.go (L164-169)
```go
func (a *AccountKeyRoleBased) Validate(currentBlockNumber uint64, r RoleType, recoveredKeys []*ecdsa.PublicKey, from common.Address) bool {
	if len(*a) > int(r) {
		return (*a)[r].Validate(currentBlockNumber, r, recoveredKeys, from)
	}
	return a.getDefaultKey().Validate(currentBlockNumber, r, recoveredKeys, from)
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

**File:** blockchain/types/transaction.go (L960-967)
```go
	gasKey, err := accKey.SigValidationGas(currentBlockNumber, accountkey.RoleFeePayer, len(pubkey))
	if err != nil {
		return 0, err
	}

	if err := accountkey.ValidateAccountKey(currentBlockNumber, feePayer, accKey, pubkey, accountkey.RoleFeePayer); err != nil {
		return 0, ErrInvalidAccountKey
	}
```
