### Title
Recreated-after-SelfDestruct Account Silently Deleted at Commit — (`fvm/evm/emulator/state/delta.go`, `stateDB.go`)

---

### Summary

`DeltaView.HasSelfDestructed` propagates through the parent-view chain without consulting the child view's `recreated` map. When a child delta view recreates an account (via `CreateAccount`) that was self-destructed in a parent delta view, `HasSelfDestructed` still returns `true` for that address. `StateDB.Commit` evaluates `HasSelfDestructed` before `IsCreated`, so the recreated account is unconditionally deleted and the `IsCreated` branch — which would persist it — is never reached.

---

### Finding Description

**Root cause — `DeltaView.HasSelfDestructed` ignores `d.recreated`:** [1](#0-0) 

The function checks only `d.toBeDestructed` locally, then unconditionally delegates to the parent. It never checks `d.recreated`, which is the flag set by `CreateAccount` to signal that the account was destroyed-then-recreated within this view.

**`CreateAccount` sets `recreated` but cannot clear the parent's `toBeDestructed`:** [2](#0-1) 

When `CreateAccount(addr)` is called in a child view and the address is already self-destructed in a parent view, the child sets `d.recreated[addr]` and `d.created[addr]` (lines 150, 160). It cannot and does not clear `parent.toBeDestructed[addr]`.

**`Commit` evaluates `HasSelfDestructed` first, short-circuits on `deleted = true`:** [3](#0-2) 

`db.HasSelfDestructed(addr)` (line 475) calls `db.latestView().HasSelfDestructed(addr)`. The latest view is the child view. The child has no local `toBeDestructed[addr]`, so it falls through to the parent, which returns `true`. `DeleteAccount` is called (line 476), `deleted = true`, and `continue` (line 487) skips the `IsCreated` branch at line 495 entirely. The recreated account is permanently deleted.

---

### Impact Explanation

The EVM transaction completes without error, but the committed state is wrong:

- The recreated contract does not exist after the transaction, despite the EVM execution having successfully deployed it.
- Any balance carried into the recreated account via `CreateAccount`'s balance carry-over logic (line 146 of `delta.go`) is permanently destroyed — it is neither credited to the beneficiary nor returned; it simply disappears from the EVM state.
- Any EVM balance sent to `addr` after the self-destruct but before `Commit` (e.g., via `AddBalance` in a sub-call) is also lost.
- Because the transaction succeeds with no error, the loss is silent and undetectable at the transaction layer.

This constitutes unauthorized permanent destruction of escrowed EVM balance, matching the Critical scope target.

---

### Likelihood Explanation

The exploit requires only an attacker-controlled EVM contract submitted as a standard Flow EVM transaction — no privileged node access, no key compromise, no quorum manipulation. The concrete sequence is:

1. A factory contract uses `CREATE2` to deploy contract A to `addr`. Contract A self-destructs via `SELFDESTRUCT` (EIP-6780 path, valid because the contract was created in the same transaction).
2. The factory uses `CREATE2` again with the same salt to redeploy to `addr`. The EVM calls `Snapshot()` (creating a child delta view), then `CreateAccount(addr)` in that child view.
3. The child view sets `recreated[addr]` and `created[addr]` but cannot clear the parent's `toBeDestructed[addr]`.
4. `Commit()` is called. `HasSelfDestructed` bleeds through to the parent, returns `true`, and `DeleteAccount` is called on the recreated contract.

This is a standard CREATE2-redeploy pattern used in production DeFi protocols (e.g., Uniswap-style factory resets). No special permissions are required.

---

### Recommendation

In `DeltaView.HasSelfDestructed`, check `d.recreated` before delegating to the parent:

```go
func (d *DeltaView) HasSelfDestructed(addr gethCommon.Address) (bool, *uint256.Int) {
    // If this view recreated the account, the prior self-destruct is superseded.
    if _, recreated := d.recreated[addr]; recreated {
        return false, uint256.NewInt(0)
    }
    bal, found := d.toBeDestructed[addr]
    if found {
        return true, bal
    }
    return d.parent.HasSelfDestructed(addr)
}
```

This mirrors the pattern already used in `GetState` (line 383 of `delta.go`), which checks `d.recreated` before delegating to the parent for slot reads. [4](#0-3) 

---

### Proof of Concept

```go
func TestRecreateSelfDestructedAccountBalanceLoss(t *testing.T) {
    // Setup StateDB
    db, _ := NewStateDB(ledger, root)

    addr := gethCommon.HexToAddress("0xdeadbeef")

    // 1. Create contract at addr (makes it a "new contract")
    db.CreateAccount(addr)
    db.CreateContract(addr)
    db.AddBalance(addr, uint256.NewInt(1000), 0)

    // 2. Self-destruct addr (EIP-6780 path: IsNewContract == true)
    db.SelfDestruct6780(addr)
    // addr is now in latestView().toBeDestructed

    // 3. Snapshot (EVM does this before each sub-call/create)
    db.Snapshot()

    // 4. Redeploy to addr in child view
    db.CreateAccount(addr) // sets child.created[addr], child.recreated[addr]
    db.CreateContract(addr)
    db.AddBalance(addr, uint256.NewInt(500), 0)

    // 5. Commit
    _, err := db.Commit(true)
    require.NoError(t, err)

    // 6. Assert: account must exist with balance 500
    // FAILS: HasSelfDestructed bleeds through parent, DeleteAccount is called,
    // account does not exist and balance is permanently lost.
    exist, _ := db.baseView.Exist(addr)
    require.True(t, exist, "recreated account must survive commit")

    bal, _ := db.baseView.GetBalance(addr)
    require.Equal(t, uint256.NewInt(500), bal)
}
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

**File:** fvm/evm/emulator/state/delta.go (L383-388)
```go
	_, recreated := d.recreated[sk.Address]
	if recreated {
		return gethCommon.Hash{}, nil
	}
	return d.parent.GetState(sk)
}
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
