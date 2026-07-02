### Title
`StateDB.Commit()` Skips Account Recreation When Account Is Both Self-Destructed and Re-Created in the Same Transaction — (`File: fvm/evm/emulator/state/stateDB.go`)

---

### Summary

When an EVM transaction recreates an existing account (e.g., deploys a contract to an address that already holds a balance), `StateDB.Commit()` deletes the account but never calls `BaseView.CreateAccount` for it. The account's balance is destroyed and the contract is not deployed. This is the direct analog to the "reserves can be re-added" class: an already-existing item is re-added without the code correctly handling the duplicate, causing critical state to be silently reset/lost.

---

### Finding Description

`DeltaView.CreateAccount` (the high-level EVM state layer) correctly detects when an account already exists and calls `SelfDestruct` on it before marking it as `created`:

```go
// fvm/evm/emulator/state/delta.go  lines 119-161
func (d *DeltaView) CreateAccount(addr gethCommon.Address) error {
    if d.IsCreated(addr) { return nil }
    exist, err := d.Exist(addr)
    ...
    if exist {
        destructed, balance := d.HasSelfDestructed(addr)
        if !destructed {
            balance, err = d.GetBalance(addr)
            err = d.SelfDestruct(addr)   // ← sets toBeDestructed[addr]
        }
        d.nonces[addr] = 0
        d.codes[addr] = nil
        d.codeHashes[addr] = gethTypes.EmptyCodeHash
        d.balances[addr] = balance       // ← balance carried over per EVM spec
        d.recreated[addr] = struct{}{}
    }
    d.dirtyAddresses[addr] = struct{}{}
    d.created[addr] = struct{}{}         // ← also marked as created
    return nil
}
```

After EVM execution, `StateDB.Commit()` flushes the delta state to `BaseView`. Its logic is:

```go
// fvm/evm/emulator/state/stateDB.go  lines 472-510
for _, addr := range sortedAddresses {
    deleted := false
    if db.HasSelfDestructed(addr) {
        err = db.baseView.DeleteAccount(addr)
        deleted = true
    }
    if deleted {
        continue          // ← unconditionally skips everything below
    }
    ...
    if db.IsCreated(addr) {
        err = db.baseView.CreateAccount(addr, bal, nonce, code, codeHash)
        continue
    }
    ...
}
```

For a recreated account, **both** `HasSelfDestructed` and `IsCreated` are true. The `if deleted { continue }` guard fires first, so `BaseView.CreateAccount` is **never