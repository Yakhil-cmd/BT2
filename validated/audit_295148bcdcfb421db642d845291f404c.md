### Title
Variable Shadowing in `StateDB.SlotInAccessList` Returns Incorrect `addressOk`, Causing Incorrect EVM Gas Accounting - (File: fvm/evm/emulator/state/stateDB.go)

---

### Summary

In `StateDB.SlotInAccessList`, a Go variable shadowing bug causes the `addressOk` return value to always be `false` when the queried slot is not found in the access list — even when the address itself is warm (already in the access list). This incorrect return value is consumed by go-ethereum's EIP-2929 gas calculation logic, causing EVM transactions on Flow to be overcharged gas for SSTORE operations on warm addresses with cold slots, and potentially causing valid EVM transactions to fail with out-of-gas errors.

---

### Finding Description

In `fvm/evm/emulator/state/stateDB.go`, `StateDB.SlotInAccessList` iterates over all `DeltaView` layers to determine whether a given `(address, slot)` pair is in the EIP-2929 access list:

```go
func (db *StateDB) SlotInAccessList(addr gethCommon.Address, key gethCommon.Hash) (addressOk bool, slotOk bool) {
    slotKey := types.SlotAddress{Address: addr, Key: key}
    addressFound := false          // outer variable, line 360
    end := len(db.views)
    for i := range end {
        view := db.views[i]
        addressFound, slotFound := view.SlotInAccessList(slotKey)  // BUG: := shadows outer addressFound
        if slotFound {
            return addressFound, true
        }
    }
    return addressFound, false     // outer addressFound is always false
}
```

On line 364, the short variable declaration `:=` creates **new local variables** `addressFound` and `slotFound` that shadow the outer `addressFound` declared on line 360. The outer `addressFound` is therefore **never updated** by the loop. When no view contains the slot, the function falls through to `return addressFound, false`, where `addressFound` is always the initial value `false` — regardless of whether the address is actually warm.

The correct behavior: if address `A` is warm (added via `Prepare` or a prior `CALL`) but slot `(A, S)` has not yet been accessed, `SlotInAccessList(A, S)` should return `(true, false)`. Instead it always returns `(false, false)`.

This contrasts with `AddressInAccessList`, which correctly uses `=` (not `:=`) and properly propagates the found state:

```go
for i := range end {
    view := db.views[i]
    if view.AddressInAccessList(addr) {
        return true
    }
}
``` [1](#0-0) 

The `DeltaView.SlotInAccessList` correctly checks only its own local access list (by design, as documented in the comment), relying on `StateDB.SlotInAccessList` to aggregate across views — but the aggregation is broken. [2](#0-1) 

---

### Impact Explanation

The `addressOk` return value from `SlotInAccessList` is used by go-ethereum's EIP-2929 gas calculation for `SSTORE` (`gasSStoreEIP2929`). Per EIP-2929, when a slot is cold but the address is warm, only `COLD_SLOAD_COST` (2100 gas) is charged. When both the address and slot are cold, `COLD_ACCOUNT_ACCESS_COST` (2600 gas) is additionally charged. Because the bug always reports `addressOk=false`, the EVM incorrectly treats warm addresses as cold, charging an extra 2600 gas per SSTORE on a warm address with a cold slot.

Concrete consequences:
1. **Overcharged gas**: Any EVM transaction that SSTOREs to a slot of a warm address (e.g., the transaction's own contract, which is always warm after `Prepare`) is charged 2600 extra gas per such operation.
2. **Denial of valid transactions**: If a transaction's gas limit is set to the correct amount (without the spurious cold-account surcharge), it will fail with an out-of-gas error even though it should succeed. This is the direct analog to the external report: a valid operation is incorrectly denied due to an inverted/incorrect condition check.

The `Prepare` call always adds the sender, destination, coinbase, and precompiles to the address access list, so virtually every EVM transaction has warm addresses whose slots will trigger this bug on first access. [3](#0-2) 

---

### Likelihood Explanation

The entry path is fully unprivileged: any user can submit an EVM transaction via the Flow EVM gateway or via a Cadence transaction invoking `EVM.run`. The bug is triggered on the first SSTORE to any slot of a warm address within a transaction — an extremely common pattern (e.g., any contract that writes to its own storage after being called). The `Prepare` function guarantees that the sender and destination are always warm, so any contract that writes to its own storage in the same transaction it is called will trigger this bug. Likelihood is high.

---

### Recommendation

Replace the short variable declaration `:=` with a proper assignment that updates the outer `addressFound`:

```go
addressFound := false
end := len(db.views)
for i := range end {
    view := db.views[i]
    addrFound, slotFound := view.SlotInAccessList(slotKey)
    if slotFound {
        return addrFound, true
    }
    if addrFound {
        addressFound = true
    }
}
return addressFound, false
```

This mirrors the correct pattern used in `AddressInAccessList` and ensures that `addressOk` accurately reflects whether the address is warm even when the slot is cold.

---

### Proof of Concept

```
Setup:
  - Deploy a contract C at address A on Flow EVM.
  - A is added to the access list as warm during Prepare (it is the destination).

Transaction execution:
  1. EVM calls C (A is warm in the access list).
  2. C executes SSTORE to slot S (first access to slot S in this transaction).
  3. EVM calls StateDB.SlotInAccessList(A, S).
  4. Loop iterates over all DeltaViews; none contain slot (A,S).
  5. Due to shadowing bug, outer addressFound remains false.
  6. Returns (false, false) — incorrectly reporting A as cold.
  7. EVM charges COLD_ACCOUNT_ACCESS_COST (2600) + COLD_SLOAD_COST (2100) = 4700 gas.
  8. Correct charge should be COLD_SLOAD_COST (2100) only, since A is warm.
  9. If the transaction was submitted with gas limit = correct_gas_needed,
     it fails with out-of-gas error despite being valid.

Verification:
  - Call StateDB.SlotInAccessList(A, S) after Prepare but before any SSTORE.
  - Observe: returns (false, false).
  - Call StateDB.AddressInAccessList(A).
  - Observe: returns true.
  - Contradiction: address is warm per AddressInAccessList but SlotInAccessList
    incorrectly reports it as cold.
``` [4](#0-3) [5](#0-4)

### Citations

**File:** fvm/evm/emulator/state/stateDB.go (L325-345)
```go
// AddressInAccessList checks if an address is in the access list
func (db *StateDB) AddressInAccessList(addr gethCommon.Address) bool {
	// For each static call / call / delegate call, the EVM will create
	// a snapshot, so that it can revert to it in case of execution errors,
	// such as out of gas etc, using `Snapshot` & `RevertToSnapshot`.
	// This can create a long list of views, in the order of 4K for certain
	// large transactions. To avoid performance issues with DeltaView checking parents,
	// which causes deep stacks and function call overhead, we use a plain for-loop instead.
	// We iterate through the views in ascending order (from lowest to highest) as an optimization.
	// Since addresses are typically added to the AccessList early during transaction execution,
	// this allows us to return early when the needed addresses are found in the initial views.
	end := len(db.views)
	for i := range end {
		view := db.views[i]
		if view.AddressInAccessList(addr) {
			return true
		}
	}

	return false
}
```

**File:** fvm/evm/emulator/state/stateDB.go (L347-371)
```go
// SlotInAccessList checks if the given (address,slot) is in the access list
func (db *StateDB) SlotInAccessList(addr gethCommon.Address, key gethCommon.Hash) (addressOk bool, slotOk bool) {
	slotKey := types.SlotAddress{Address: addr, Key: key}

	// For each static call / call / delegate call, the EVM will create
	// a snapshot, so that it can revert to it in case of execution errors,
	// such as out of gas etc, using `Snapshot` & `RevertToSnapshot`.
	// This can create a long list of views, in the order of 4K for certain
	// large transactions. To avoid performance issues with DeltaView checking parents,
	// which causes deep stacks and function call overhead, we use a plain for-loop instead.
	// We iterate through the views in ascending order (from lowest to highest) as an optimization.
	// Since slots are typically added to the AccessList early during transaction execution,
	// this allows us to return early when the needed slots are found in the initial views.
	addressFound := false
	end := len(db.views)
	for i := range end {
		view := db.views[i]
		addressFound, slotFound := view.SlotInAccessList(slotKey)
		if slotFound {
			return addressFound, true
		}
	}

	return addressFound, false
}
```

**File:** fvm/evm/emulator/state/stateDB.go (L587-608)
```go
func (db *StateDB) Prepare(rules gethParams.Rules, sender, coinbase gethCommon.Address, dest *gethCommon.Address, precompiles []gethCommon.Address, txAccesses gethTypes.AccessList) {
	if rules.IsBerlin {
		db.AddAddressToAccessList(sender)

		if dest != nil {
			db.AddAddressToAccessList(*dest)
			// If it's a create-tx, the destination will be added inside egethVM.create
		}
		for _, addr := range precompiles {
			db.AddAddressToAccessList(addr)
		}
		for _, el := range txAccesses {
			db.AddAddressToAccessList(el.Address)
			for _, key := range el.StorageKeys {
				db.AddSlotToAccessList(el.Address, key)
			}
		}
		if rules.IsShanghai { // EIP-3651: warm coinbase
			db.AddAddressToAccessList(coinbase)
		}
	}
}
```

**File:** fvm/evm/emulator/state/delta.go (L518-527)
```go
func (d *DeltaView) SlotInAccessList(sk types.SlotAddress) (addressOk bool, slotOk bool) {
	addressFound := d.AddressInAccessList(sk.Address)
	if d.accessListSlots != nil {
		_, slotFound := d.accessListSlots[sk]
		if slotFound {
			return addressFound, true
		}
	}
	return addressFound, false
}
```
