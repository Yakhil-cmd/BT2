### Title
Recreated Account Permanently Deleted in `StateDB.Commit` Due to Missing Recreated-Case Handling — (`fvm/evm/emulator/state/stateDB.go`)

---

### Summary

`StateDB.Commit` unconditionally skips the `IsCreated` branch whenever `HasSelfDestructed` is true. `DeltaView.CreateAccount` on an already-existing address sets **both** `toBeDestructed[addr]` and `created[addr]` (the "recreated" case). At commit time the account is deleted from the base view and the `continue` on line 487 prevents the subsequent `IsCreated` branch from ever running, so the account is never recreated. The result is a silently-deleted account with a lost carried-over balance.

---

### Finding Description

**Step 1 — `DeltaView.CreateAccount` produces the inconsistent state**

When `CreateAccount` is called on an address that already exists in the parent view (e.g. a pre-funded CREATE2 target), the function:

1. Calls `d.SelfDestruct(addr)` at line 136, which writes `toBeDestructed[addr] = balance`.
2. Sets `d.recreated[addr] = struct{}{}` at line 150.
3. Sets `d.created[addr] = struct{}{}` at line 160.

After this call the address is simultaneously in `toBeDestructed` **and** `created`. [1](#0-0) 

**Step 2 — `StateDB.Commit` never reaches the `IsCreated` branch for recreated accounts**

The commit loop processes every dirty address. For a recreated address:

- Line 475: `HasSelfDestructed(addr)` returns `true` (because `toBeDestructed[addr]` is set).
- Line 476: `baseView.DeleteAccount(addr)` permanently removes the account.
- Line 484: `deleted = true`.
- Lines 486–488: `if deleted { continue }` — the loop moves to the next address.
- Lines 495–511: The `IsCreated` branch that would call `baseView.CreateAccount(...)` is **never reached**. [2](#0-1) 

The `recreated` map tracked in `DeltaView` is only consulted in `GetState` to suppress stale storage reads; it is never checked in `StateDB.Commit`. [3](#0-2) 

**Step 3 — `Extract` cannot see the account**

`Extract` iterates the `baseView` account iterator. Because the account was deleted and never recreated in the base view, it is invisible to `Extract` and to any subsequent transaction. [4](#0-3) 

---

### Impact Explanation

- A contract deployed via `CREATE2` to a pre-funded address (a common, legitimate pattern) appears to succeed — the EVM returns no error — but the account is silently erased from the base view after `Commit`.
- The carried-over balance (captured in `toBeDestructed[addr]` and written back to `d.balances[addr]` at line 146) is lost; it is neither transferred nor preserved.
- All subsequent calls to the contract fail because the account does not exist in the base view.
- `Extract` omits the account entirely, breaking any state-proof or cross-layer accounting that relies on it.

---

### Likelihood Explanation

The trigger is a standard EVM pattern: send ETH to a deterministic CREATE2 address before deploying the contract. This is used by factory contracts, counterfactual wallets, and protocol bridges. No privileged access is required; any EVM transaction submitted through the normal Flow EVM transaction path can reach this code.

---

### Recommendation

In `StateDB.Commit`, after deleting a self-destructed account, check whether the address is also marked as created (the recreated case). If so, proceed to call `baseView.CreateAccount` with the current balance, nonce, code, and code hash instead of `continue`-ing. Concretely, replace the unconditional `if deleted { continue }` guard with logic that checks `db.IsCreated(addr)` and, when true, falls through to the creation branch after the deletion.

---

### Proof of Concept

```
1. NewStateDB → CreateAccount(A), AddBalance(A, 100), Commit(true)
   // A is now in the base view with balance 100

2. db.Reset() (or new StateDB on same ledger)
   // Simulates a new transaction

3. db.CreateAccount(A)
   // DeltaView: toBeDestructed[A]=100, created[A]={}, recreated[A]={}

4. db.SetCode(A, someCode)
   db.AddBalance(A, 50)   // new balance = 50 (carried-over 100 was zeroed by SelfDestruct)

5. db.Commit(true)
   // HasSelfDestructed(A)=true → DeleteAccount(A), deleted=true → continue
   // IsCreated(A) branch never runs → A is gone from base view

6. Extract(root, baseView)
   // A is absent; balance 100 is lost; contract code is lost
```

### Citations

**File:** fvm/evm/emulator/state/delta.go (L128-161)
```go
	if exist {
		// check if already destructed
		destructed, balance := d.HasSelfDestructed(addr)
		if !destructed {
			balance, err = d.GetBalance(addr)
			if err != nil {
				return err
			}
			err = d.SelfDestruct(addr)
			if err != nil {
				return err
			}
		}

		d.nonces[addr] = 0
		d.codes[addr] = nil
		d.codeHashes[addr] = gethTypes.EmptyCodeHash
		// carrying over the balance. (legacy behavior of the Geth stateDB)
		d.balances[addr] = balance

		// flag addr as recreated, this flag helps with postponing deletion of slabs
		// otherwise we have to iterate over all slabs of this account and set the to nil
		d.recreated[addr] = struct{}{}

		// remove slabs from cache related to this account
		for k := range d.slots {
			if k.Address == addr {
				delete(d.slots, k)
			}
		}
	}
	d.dirtyAddresses[addr] = struct{}{}
	d.created[addr] = struct{}{}
	return nil
```

**File:** fvm/evm/emulator/state/delta.go (L383-387)
```go
	_, recreated := d.recreated[sk.Address]
	if recreated {
		return gethCommon.Hash{}, nil
	}
	return d.parent.GetState(sk)
```

**File:** fvm/evm/emulator/state/stateDB.go (L472-511)
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

		bal := db.GetBalance(addr)
		nonce := db.GetNonce(addr)
		code := db.GetCode(addr)
		codeHash := db.GetCodeHash(addr)
		// create new accounts
		if db.IsCreated(addr) {
			err = db.baseView.CreateAccount(
				addr,
				bal,
				nonce,
				code,
				codeHash,
			)
			if err != nil {
				return nil, wrapError(err)
			}
			err = updateCommitter.CreateAccount(addr, bal, nonce, codeHash)
			if err != nil {
				return nil, wrapError(err)
			}
			continue
		}
```

**File:** fvm/evm/emulator/state/extract.go (L17-37)
```go
	itr, err := baseView.AccountIterator()

	if err != nil {
		return nil, err
	}
	// make a list of accounts with storage
	addrWithSlots := make([]gethCommon.Address, 0)
	for {
		// TODO: we can optimize by returning the encoded value
		acc, err := itr.Next()
		if err != nil {
			return nil, err
		}
		if acc == nil {
			break
		}
		if acc.HasStoredValues() {
			addrWithSlots = append(addrWithSlots, acc.Address)
		}
		accounts[acc.Address] = acc
	}
```
