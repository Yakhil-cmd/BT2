### Title
`StateDB.Commit` Skips Account Recreation After Self-Destruct, Causing Silent EVM Asset Loss - (File: `fvm/evm/emulator/state/stateDB.go`)

---

### Summary

`StateDB.Commit` contains a state-ordering bug that is the direct Go/EVM analog of the reported Solidity mapping-clear vulnerability. When an EVM account is both self-destructed **and** recreated within the same transaction — a sequence that `DeltaView.CreateAccount` explicitly supports and records — the `if deleted { continue }` guard at line 486 unconditionally skips the `IsCreated` branch. The old account is deleted from persistent storage, but the new account is never written. Any ETH balance carried over into the recreated account is permanently destroyed, and the contract deployment silently produces no on-chain artifact.

---

### Finding Description

**Root cause in `DeltaView.CreateAccount`** (`fvm/evm/emulator/state/delta.go`, lines 119–161):

When `CreateAccount` is called on an address that already exists, the function:
1. Calls `SelfDestruct(addr)` → inserts `addr` into `d.toBeDestructed` (line 136).
2. Sets `d.recreated[addr]` (line 150) — an explicit flag meaning "destroyed then reborn".
3. Sets `d.created[addr]` (line 160).

After this call, both `HasSelfDestructed(addr)` and `IsCreated(addr)` return `true` for the same address in the same delta view.

**Root cause in `StateDB.Commit`** (`fvm/evm/emulator/state/stateDB.go`, lines 472–526):

```go
for _, addr := range sortedAddresses {
    deleted := false
    if db.HasSelfDestructed(addr) {          // true  (toBeDestructed set)
        err = db.baseView.DeleteAccount(addr) // old account erased
        ...
        deleted = true
    }
    if deleted {
        continue                              // ← unconditionally skips IsCreated
    }
    ...
    if db.IsCreated(addr) {                  // NEVER REACHED for recreated accounts
        err = db.baseView.CreateAccount(...)  // new account never written
        ...
    }
}
```

The `if deleted { continue }` guard does not distinguish between a pure self-destruct (account gone forever) and a recreate (destroy-then-create). Because `DeltaView.CreateAccount` places the address in **both** `toBeDestructed` and `created`, the commit loop deletes the old account and then skips the creation of the new one. The `recreated` flag recorded in `DeltaView` is never consulted by `Commit`.

The slot-update loop has the same blind spot:

```go
for _, sk := range sortedSlots {
    if db.HasSelfDestructed(sk.Address) {  // true for recreated accounts
        continue                            // new contract's storage never written
    }
    ...
}
```

So even if the account were somehow created, its storage slots would also be silently dropped.

---

### Impact Explanation

**Cross-VM asset loss.** `DeltaView.CreateAccount` explicitly carries the pre-destruction balance into the recreated account (`d.balances[addr] = balance`, line 146). After `Commit`, `DeleteAccount` removes that balance from persistent storage and `CreateAccount` is never called, so the balance is permanently destroyed. Any FLOW-backed ETH held at that address is irrecoverably lost.

**Silent contract deployment failure.** The EVM transaction returns no error — `Commit` succeeds — but the deployed contract does not exist in the base view. Subsequent calls to the address will behave as if it is an empty EOA. No revert, no error, no event distinguishes this from a successful deployment.

**EVM state divergence.** The delta-view layer reports the account as existing (with code, balance, nonce) for the remainder of the transaction, while the committed base view has no account at that address. Any off-chain indexer or cross-VM bridge that reads committed state will observe a different world than the EVM execution layer.

---

### Likelihood Explanation

The trigger is reachable by any unprivileged EVM transaction sender. The standard scenario is:

1. ETH is sent to a deterministic `CREATE2` address before the contract is deployed (a common DeFi pattern for pre-funding factory-deployed pairs, vaults, or proxy contracts).
2. A subsequent transaction deploys the contract to that address via `CREATE2`.

Step 2 causes the EVM to call `StateDB.CreateAccount` on an address that already has a balance, which internally calls `DeltaView.CreateAccount` → `SelfDestruct` + `created`. `Commit` then deletes the account and skips recreation.

The pattern is also triggered by any `CREATE` opcode that resolves to an address with a pre-existing nonce or balance (possible via address collision or deliberate pre-seeding). No privileged access, no staked node compromise, and no admin key is required.

---

### Recommendation

In `StateDB.Commit`, after deleting a self-destructed account, check whether the address was also recreated (`IsCreated` returns true). If so, fall through to the creation branch instead of skipping it:

```go
if db.HasSelfDestructed(addr) {
    err = db.baseView.DeleteAccount(addr)
    if err != nil {
        return nil, wrapError(err)
    }
    err = updateCommitter.DeleteAccount(addr)
    if err != nil {
        return nil, wrapError(err)
    }
    if !db.IsCreated(addr) {   // only skip if NOT recreated
        continue
    }
    // fall through: recreated account must also be created below
}
```

Apply the same fix to the slot-update loop: skip slot writes only when the account was purely self-destructed, not when it was recreated.

---

### Proof of Concept

```
Transaction T:
  1. addr X already exists in base view with balance B (e.g., pre-funded via a prior tx).
  2. EVM executes CREATE2 targeting addr X.
     → gethVM calls StateDB.CreateAccount(X)
     → DeltaView.CreateAccount(X):
         SelfDestruct(X)  → toBeDestructed[X] = B
         recreated[X]     = {}
         created[X]       = {}
         balances[X]      = B   (carried over)
  3. Constructor runs; code and storage slots are set in the delta view.
  4. proc.commit(true) → StateDB.Commit(true):
       HasSelfDestructed(X) == true
         → baseView.DeleteAccount(X)   ✓ old account erased
         → deleted = true
       if deleted { continue }          ← skips IsCreated branch
       IsCreated(X) never checked       ← new account never written
       Slot loop: HasSelfDestructed(X) == true → slots skipped

After T commits:
  - baseView has no account at X.
  - Balance B is gone.
  - Contract code is gone.
  - Tx receipt shows success (no error from Commit).
  - Any call to X behaves as if X is an empty address.
``` [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4)

### Citations

**File:** fvm/evm/emulator/state/delta.go (L119-161)
```go
func (d *DeltaView) CreateAccount(addr gethCommon.Address) error {
	// if is already created return
	if d.IsCreated(addr) {
		return nil
	}
	exist, err := d.Exist(addr)
	if err != nil {
		return err
	}
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

**File:** fvm/evm/emulator/state/stateDB.go (L495-511)
```go
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

**File:** fvm/evm/emulator/state/stateDB.go (L542-546)
```go
	for _, sk := range sortedSlots {
		// don't update slots if self destructed
		if db.HasSelfDestructed(sk.Address) {
			continue
		}
```

**File:** fvm/evm/emulator/emulator.go (L363-379)
```go
// commit commits the changes to the state (with optional finalization)
func (proc *procedure) commit(finalize bool) (hash.Hash, error) {
	// Calling `StateDB.Finalise(true)` is currently a no-op, but
	// we add it here to be more in line with how its envisioned.
	proc.state.Finalise(true)
	stateUpdateCommitment, err := proc.state.Commit(finalize)
	if err != nil {
		// if known types (state errors) don't do anything and return
		if types.IsAFatalError(err) || types.IsAStateError(err) || types.IsABackendError(err) {
			return stateUpdateCommitment, err
		}

		// else is a new fatal error
		return stateUpdateCommitment, types.NewFatalError(err)
	}
	return stateUpdateCommitment, nil
}
```
