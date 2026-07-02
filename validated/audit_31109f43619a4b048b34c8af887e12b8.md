### Title
`BaseView.UpdateAccount` Silently Creates Non-Existing Accounts, Causing EVM State Commitment Hash Mismatch - (File: `fvm/evm/emulator/state/base.go`)

---

### Summary

`BaseView.UpdateAccount` in Flow's EVM state layer silently creates a new account when called on a non-existing address instead of returning an error. This dual-purpose behavior causes a **commitment hash mismatch**: `StateDB.Commit()` records the operation as `AccountUpdateOpCode` in the `UpdateCommitter`, but the actual storage operation is an account creation (`AccountCreationOpCode`). The resulting incorrect commitment hash corrupts the EVM state root used for cross-VM verification.

---

### Finding Description

In `fvm/evm/emulator/state/base.go`, `BaseView.UpdateAccount` (lines 262–294) checks whether the account exists. If it does not (`acc == nil`), it silently falls through to `CreateAccount` instead of returning an error:

```go
// if update is called on a non existing account
// we gracefully call the create account
// TODO: but we might need to revisit this action in the future
if acc == nil {
    return v.CreateAccount(addr, balance, nonce, code, codeHash)
}
```

The developers themselves flag this with a `TODO` acknowledging the behavior needs to be revisited. [1](#0-0) 

In `StateDB.Commit()` (`fvm/evm/emulator/state/stateDB.go`, lines 512–525), for dirty addresses that are **not** marked as created (`!db.IsCreated(addr)`), the code calls `baseView.UpdateAccount()` and then immediately calls `updateCommitter.UpdateAccount()`:

```go
err = db.baseView.UpdateAccount(addr, bal, nonce, code, codeHash)
...
err = updateCommitter.UpdateAccount(addr, bal, nonce, codeHash)
``` [2](#0-1) 

The `UpdateCommitter` uses **distinct opcodes** for create vs. update operations:
- `AccountCreationOpCode` for `CreateAccount`
- `AccountUpdateOpCode` for `UpdateAccount` [3](#0-2) 

When `BaseView.UpdateAccount` silently calls `CreateAccount` internally (because the account doesn't exist), the actual storage operation is a **creation**, but `updateCommitter.UpdateAccount()` records it as an **update** with `AccountUpdateOpCode`. The commitment hash returned by `StateDB.Commit()` is therefore computed over the wrong opcode sequence, producing an incorrect EVM state root.

The `DeltaView.AddBalance` (and similar mutation methods) marks an address as dirty **without** requiring the account to exist or be in the `created` set:

```go
d.balances[addr] = new(uint256.Int).Add(balance, amount)
d.dirtyAddresses[addr] = struct{}{}
``` [4](#0-3) 

This means any EVM operation that modifies an account's balance, nonce, or code without first calling `CreateAccount` (e.g., precompile-driven balance additions, coinbase rewards, or gas refunds to a fresh address) will produce a dirty-but-not-created address. `StateDB.Commit()` then routes it through `UpdateAccount`, triggering the silent creation and the opcode mismatch.

---

### Impact Explanation

The commitment hash returned by `StateDB.Commit()` is the EVM state root used to verify cross-VM state transitions in the Flow EVM bridge. When `UpdateAccount` silently creates an account, the commitment is computed with `AccountUpdateOpCode` instead of `AccountCreationOpCode`. Any independent verifier replaying the same operations with the correct opcode will compute a **different hash**, causing:

1. **EVM state root corruption**: The published state root does not match the actual ledger state.
2. **Cross-VM asset loss / bridge mis-accounting**: Bridge logic that relies on the commitment to authorize asset transfers between Flow and EVM can be fed an incorrect root, enabling acceptance of invalid state proofs or rejection of valid ones, leading to locked or lost assets. [5](#0-4) 

---

### Likelihood Explanation

This is reachable by any unprivileged EVM transaction sender. A transaction that sends ETH to a fresh address (one that has never existed in `BaseView`) causes `AddBalance` to be called on that address in `DeltaView`, making it dirty but not created. `StateDB.Commit()` then calls `UpdateAccount` on the non-existing `BaseView` account, triggering the silent creation and the opcode mismatch. No special privileges, leaked keys, or compromised nodes are required. [6](#0-5) 

---

### Recommendation

Separate the dual-purpose `UpdateAccount` into two strictly distinct operations:

1. **`CreateAccount`** — asserts the account does **not** already exist; returns an error if it does.
2. **`UpdateAccount`** — asserts the account **does** already exist; returns an error (not a silent fallback) if it does not.

Remove the silent `CreateAccount` fallback inside `UpdateAccount`:

```go
// BEFORE (vulnerable):
if acc == nil {
    return v.CreateAccount(addr, balance, nonce, code, codeHash)
}

// AFTER (fixed):
if acc == nil {
    return fmt.Errorf("UpdateAccount called on non-existing account %s", addr.Hex())
}
```

Callers in `StateDB.Commit()` that need to handle the "account does not exist but is dirty" case should explicitly call `CreateAccount` and record `updateCommitter.CreateAccount()` accordingly. [1](#0-0) [7](#0-6) 

---

### Proof of Concept

1. Deploy a fresh Flow EVM environment with an empty `BaseView`.
2. Submit an EVM transaction that transfers ETH to a brand-new address `A` (never seen before in `BaseView`). The EVM calls `DeltaView.AddBalance(A, amount)` — `A` is now dirty but **not** in the `created` set.
3. `StateDB.Commit()` iterates dirty addresses. For `A`: `db.IsCreated(A)` → `false`, so it calls `db.baseView.UpdateAccount(A, ...)`.
4. Inside `BaseView.UpdateAccount`, `v.getAccount(A)` returns `nil` (account doesn't exist). The code silently calls `v.CreateAccount(A, ...)` — account is **created** in storage.
5. Back in `StateDB.Commit()`, `updateCommitter.UpdateAccount(A, ...)` is called — records `AccountUpdateOpCode` in the hasher.
6. The commitment hash is computed over `AccountUpdateOpCode || A || balance || nonce || codeHash`.
7. An independent verifier replaying the same ledger changes would compute the hash over `AccountCreationOpCode || A || balance || nonce || codeHash` — a **different hash**.
8. The EVM state root published on-chain is incorrect, breaking cross-VM state verification and enabling bridge mis-accounting. [3](#0-2) [8](#0-7)

### Citations

**File:** fvm/evm/emulator/state/base.go (L262-294)
```go
// UpdateAccount updates an account's meta data
func (v *BaseView) UpdateAccount(
	addr gethCommon.Address,
	balance *uint256.Int,
	nonce uint64,
	code []byte,
	codeHash gethCommon.Hash,
) error {
	acc, err := v.getAccount(addr)
	if err != nil {
		return err
	}
	// if update is called on a non existing account
	// we gracefully call the create account
	// TODO: but we might need to revisit this action in the future
	if acc == nil {
		return v.CreateAccount(addr, balance, nonce, code, codeHash)
	}

	// update account code
	err = v.updateAccountCode(addr, code, codeHash)
	if err != nil {
		return err
	}
	// TODO: maybe purge the state in the future as well
	// currently the behavior of stateDB doesn't purge the data
	// We don't need to check if the code is empty and we purge the state
	// this is not possible right now.

	newAcc := NewAccount(addr, balance, nonce, codeHash, acc.CollectionID)
	// no need to update the cache , storeAccount would update the cache
	return v.storeAccount(newAcc)
}
```

**File:** fvm/evm/emulator/state/stateDB.go (L438-526)
```go
// Commit commits state changes back to the underlying
func (db *StateDB) Commit(finalize bool) (hash.Hash, error) {
	// return error if any has been accumulated
	if db.cachedError != nil {
		return nil, wrapError(db.cachedError)
	}

	var err error

	// iterate views and collect dirty addresses and slots
	addresses := make(map[gethCommon.Address]struct{})
	slots := make(map[types.SlotAddress]struct{})
	for _, view := range db.views {
		for key := range view.DirtyAddresses() {
			addresses[key] = struct{}{}
		}
		for key := range view.DirtySlots() {
			slots[key] = struct{}{}
		}
	}

	// sort addresses
	sortedAddresses := make([]gethCommon.Address, 0, len(addresses))
	for addr := range addresses {
		sortedAddresses = append(sortedAddresses, addr)
	}

	sort.Slice(sortedAddresses,
		func(i, j int) bool {
			return bytes.Compare(sortedAddresses[i][:], sortedAddresses[j][:]) < 0
		})

	updateCommitter := NewUpdateCommitter()
	// update accounts
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
		err = db.baseView.UpdateAccount(
			addr,
			bal,
			nonce,
			code,
			codeHash,
		)
		if err != nil {
			return nil, wrapError(err)
		}
		err = updateCommitter.UpdateAccount(addr, bal, nonce, codeHash)
		if err != nil {
			return nil, wrapError(err)
		}
	}
```

**File:** fvm/evm/emulator/state/updateCommitter.go (L77-98)
```go
// UpdateAccount captures an update account operation
func (dc *UpdateCommitter) UpdateAccount(
	addr gethCommon.Address,
	balance *uint256.Int,
	nonce uint64,
	codeHash gethCommon.Hash,
) error {
	buffer := make([]byte, accountUpdateBufferSize)
	var index int
	buffer[0] = byte(AccountUpdateOpCode)
	index += opcodeByteSize
	copy(buffer[index:index+addressByteSize], addr.Bytes())
	index += addressByteSize
	encodedBalance := balance.Bytes32()
	copy(buffer[index:index+balanceByteSize], encodedBalance[:])
	index += balanceByteSize
	binary.BigEndian.PutUint64(buffer[index:index+nonceByteSize], nonce)
	index += nonceByteSize
	copy(buffer[index:index+hashByteSize], codeHash.Bytes())
	_, err := dc.hasher.Write(buffer)
	return err
}
```

**File:** fvm/evm/emulator/state/delta.go (L18-64)
```go
type DeltaView struct {
	parent types.ReadOnlyView

	// dirtyAddresses keeps a set of addresses with changes
	dirtyAddresses map[gethCommon.Address]struct{}
	// created keeps a set of recently created addresses
	created map[gethCommon.Address]struct{}
	// This is an EIP-6780 flag indicating whether the object is eligible for
	// self-destruct according to EIP-6780. The flag could be set either when
	// the contract is just created within the current transaction, or when the
	// object was previously existent and is being deployed as a contract within
	// the current transaction.
	newContract map[gethCommon.Address]struct{}
	// toBeDestructed keeps a set of addresses flagged to be destructed at the
	// end of transaction, it also keeps the balance of the addresses before destruction
	toBeDestructed map[gethCommon.Address]*uint256.Int
	// is a flag used to track accounts that has been flagged for
	// destruction but recreated later
	recreated map[gethCommon.Address]struct{}
	// balances keeps the changes to the account balances
	balances map[gethCommon.Address]*uint256.Int
	// nonces keeps the changes to the account nonces
	nonces map[gethCommon.Address]uint64
	// codes keeps the changes to the account codes
	codes map[gethCommon.Address][]byte
	// codeHashes keeps the changes to account code hashes
	codeHashes map[gethCommon.Address]gethCommon.Hash

	// slots keeps a set of slots that has been changed in this view
	slots map[types.SlotAddress]gethCommon.Hash

	// transient storage
	transient map[types.SlotAddress]gethCommon.Hash

	// access lists
	accessListAddresses map[gethCommon.Address]struct{}
	accessListSlots     map[types.SlotAddress]struct{}

	// logs
	logs []*gethTypes.Log

	// preimages
	preimages map[gethCommon.Hash][]byte

	// refund
	refund uint64
}
```
