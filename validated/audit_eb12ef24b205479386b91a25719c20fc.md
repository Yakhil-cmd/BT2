### Title
`HasSelfDestructed` Ignores `recreated` Flag, Causing Silent Slot Loss and Account Deletion for Recreated Contracts — (`fvm/evm/emulator/state/delta.go`, `stateDB.go`)

---

### Summary

`DeltaView.HasSelfDestructed` propagates up the parent-view chain without checking whether the address was subsequently recreated in a child view. When `Commit()` calls `db.HasSelfDestructed(addr)` it always finds the self-destruct flag from the parent view, even when a later child view has set `recreated[addr]`. This causes `Commit()` to (1) delete the account instead of creating it, and (2) skip all storage-slot writes for that address — both silently, with no error.

---

### Finding Description

**Root cause — `DeltaView.HasSelfDestructed` does not check `recreated`** [1](#0-0) 

```go
func (d *DeltaView) HasSelfDestructed(addr gethCommon.Address) (bool, *uint256.Int) {
    bal, found := d.toBeDestructed[addr]
    if found {
        return true, bal
    }
    return d.parent.HasSelfDestructed(addr)   // ← never checks d.recreated[addr]
}
```

When `CreateAccount` is called on an already-destructed address in a child view, it sets `d.recreated[addr]` to signal that the self-destruct is superseded: [2](#0-1) 

`GetState` correctly consults `recreated` to avoid reading stale parent slots: [3](#0-2) 

But `HasSelfDestructed` never does. It blindly walks up to the parent and returns `true` even though the child view has already recreated the account.

**How `Commit()` is affected**

`Commit()` calls `db.HasSelfDestructed` (which delegates to `latestView().HasSelfDestructed`) for every dirty address and every dirty slot: [4](#0-3) [5](#0-4) 

Because `HasSelfDestructed` returns `true` for the recreated address, `Commit()`:
1. Calls `baseView.DeleteAccount(addr)` and sets `deleted = true`, then `continue` — the `IsCreated` branch is never reached, so the account is never recreated in persistent state.
2. Skips every slot written after recreation with a silent `continue`.

**Concrete call sequence**

```
// view[0] is the initial DeltaView
CreateAccount(A)          // deploy contract A via CREATE2
CreateContract(A)         // marks A as newContract (EIP-6780 eligible)
SelfDestruct6780(A)       // view[0].toBeDestructed[A] = balance

snap := Snapshot()        // view[1] = NewChildView(view[0])

CreateAccount(A)          // view[1]: HasSelfDestructed(A) → true (from view[0])
                          //          sets view[1].recreated[A], view[1].created[A]
SetState(A, key, value)   // view[1].slots[{A,key}] = value  (dirty slot collected)

Commit()
  // address A: HasSelfDestructed(A) → view[1].toBeDestructed missing
  //            → view[0].toBeDestructed[A] found → true
  //            → DeleteAccount(A), deleted=true, continue   ← WRONG
  // slot {A,key}: HasSelfDestructed(A) → true → continue   ← WRONG
```

`SelfDestruct6780` is the only reachable self-destruct path in Flow EVM — legacy `SelfDestruct` is explicitly rejected: [6](#0-5) 

`SelfDestruct6780` calls `latestView().SelfDestruct(addr)` only when `IsNewContract(addr)` is true, which is set by `CreateContract`: [7](#0-6) 

This is a standard EVM pattern: deploy via CREATE2, self-destruct, redeploy to the same address in the same transaction.

---

### Impact Explanation

- **Account deletion instead of recreation**: the recreated contract does not exist in persistent state after the transaction.
- **Silent slot loss**: every `SSTORE` executed after the recreation is discarded without error. The contract's execution sees the writes succeed (no revert), but they are never committed.
- **EVM resource accounting corruption**: the EVM's view of state diverges from what is actually stored, breaking any invariant that relies on storage written by a recreated contract.

---

### Likelihood Explanation

The trigger is a well-known EVM pattern (CREATE2 → SELFDESTRUCT → CREATE2 at same address within one transaction). It is reachable through normal EVM transaction submission on Flow — no privileged access, no staked-node compromise, and no admin keys are required. An attacker-controlled contract can execute this sequence autonomously.

---

### Recommendation

In `DeltaView.HasSelfDestructed`, check `d.recreated` before delegating to the parent. If the address was recreated in this view, the parent's self-destruct flag is superseded and the function must return `false`:

```go
func (d *DeltaView) HasSelfDestructed(addr gethCommon.Address) (bool, *uint256.Int) {
    bal, found := d.toBeDestructed[addr]
    if found {
        return true, bal
    }
    // Recreation in this view supersedes any self-destruct in a parent view.
    if _, recreated := d.recreated[addr]; recreated {
        return false, nil
    }
    return d.parent.HasSelfDestructed(addr)
}
```

This mirrors the existing pattern in `GetState`: [3](#0-2) 

---

### Proof of Concept

A differential test comparing Flow `StateDB` against a reference Geth `statedb` for the sequence below would expose the divergence:

```go
// Flow StateDB
db, _ := NewStateDB(ledger, root)
db.CreateAccount(addrA)
db.CreateContract(addrA)
db.SelfDestruct6780(addrA)          // marks addrA in view[0]
snap := db.Snapshot()               // view[1]
db.CreateAccount(addrA)             // recreates in view[1]
db.SetState(addrA, slotKey, val)    // writes slot in view[1]
db.Commit(true)

// After commit: db.GetState(addrA, slotKey) should equal val
// Actual result: zero (slot was skipped) and account does not exist
_ = snap // suppress unused warning
```

Assert `db.GetState(addrA, slotKey) == val` — this assertion fails on the unpatched code, confirming the slot is silently discarded and the account is deleted rather than recreated.

### Citations

**File:** fvm/evm/emulator/state/delta.go (L148-157)
```go
		// flag addr as recreated, this flag helps with postponing deletion of slabs
		// otherwise we have to iterate over all slabs of this account and set the to nil
		d.recreated[addr] = struct{}{}

		// remove slabs from cache related to this account
		for k := range d.slots {
			if k.Address == addr {
				delete(d.slots, k)
			}
		}
```

**File:** fvm/evm/emulator/state/delta.go (L195-201)
```go
func (d *DeltaView) HasSelfDestructed(addr gethCommon.Address) (bool, *uint256.Int) {
	bal, found := d.toBeDestructed[addr]
	if found {
		return true, bal
	}
	return d.parent.HasSelfDestructed(addr)
}
```

**File:** fvm/evm/emulator/state/delta.go (L382-388)
```go
	// over all the state slabs and delete them.
	_, recreated := d.recreated[sk.Address]
	if recreated {
		return gethCommon.Hash{}, nil
	}
	return d.parent.GetState(sk)
}
```

**File:** fvm/evm/emulator/state/stateDB.go (L111-114)
```go
func (db *StateDB) SelfDestruct(addr gethCommon.Address) uint256.Int {
	db.handleError(fmt.Errorf("legacy self destruct is not supported"))
	return uint256.Int{}
}
```

**File:** fvm/evm/emulator/state/stateDB.go (L119-130)
```go
func (db *StateDB) SelfDestruct6780(addr gethCommon.Address) (uint256.Int, bool) {
	balance, err := db.latestView().GetBalance(addr)
	db.handleError(err)

	if db.IsNewContract(addr) {
		err := db.latestView().SelfDestruct(addr)
		db.handleError(err)
		return *balance, true
	}

	return *balance, false
}
```

**File:** fvm/evm/emulator/state/stateDB.go (L472-488)
```go
	for _, addr := range sortedAddresses {
		deleted := false
		// first we need to delete accounts
		if db.HasSelfDestructed(addr) {
			err = db.baseView.DeleteAccount(addr)
			if err != nil {
				return nil, wrapError(err)
			}
			err = updateCommitter.DeleteAccount(addr)
			if err != nil {
				return nil, wrapError(err)
			}
			deleted = true
		}
		if deleted {
			continue
		}
```

**File:** fvm/evm/emulator/state/stateDB.go (L542-546)
```go
	for _, sk := range sortedSlots {
		// don't update slots if self destructed
		if db.HasSelfDestructed(sk.Address) {
			continue
		}
```
