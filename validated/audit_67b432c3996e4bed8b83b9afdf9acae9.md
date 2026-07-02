### Title
EVM Storage Account Unconditionally Exempt from Storage Limit Enforcement Allows Unbounded Ledger Growth Without FLOW Token Backing - (File: `fvm/transactionStorageLimiter.go`)

---

### Summary

`fvm/transactionStorageLimiter.go` contains a hard-coded exemption that permanently skips the EVM storage account (`sc.EVMStorage.Address`) from all storage-capacity enforcement. Because EVM gas fees are routed to a caller-supplied coinbase EVM address rather than to the EVM storage account's FLOW balance, the EVM storage account's on-chain capacity never grows in proportion to the state it accumulates. Any unprivileged user can call the publicly accessible `EVM.run()` entry point to write unbounded EVM state (new accounts, contract bytecode, storage slots) to the EVM storage address at a cost that is entirely decoupled from the Flow storage-fee model, violating the protocol invariant that every account's storage usage must be backed by FLOW tokens.

---

### Finding Description

Flow's storage-fee model requires that every account's storage usage (`storage.used`) must not exceed its storage capacity, which is derived from the account's FLOW token balance. This is enforced post-transaction by `TransactionStorageLimiter.CheckStorageLimits` in `fvm/transactionStorageLimiter.go`.

The function `getStorageCheckAddresses` iterates over every register written during a transaction and collects the owning addresses for the capacity check. Before adding an address to the check list it calls `shouldSkipSpecialAddress`:

```go
// fvm/transactionStorageLimiter.go  lines 171-176
func (limiter TransactionStorageLimiter) shouldSkipSpecialAddress(
    ctx Context,
    address flow.Address,
    sc *systemcontracts.SystemContracts,
) bool {
    return sc.EVMStorage.Address == address
}
```

The comment on the function reads: *"This is currently only the EVM storage address. This is a temporary solution."*

All EVM state — EVM account balances, nonces, contract bytecode, and storage slots — is stored as registers owned by `sc.EVMStorage.Address`. Whenever `EVM.run()` executes an EVM transaction that creates a new EVM account, deploys a contract, or writes a storage slot, those writes land in the EVM storage account's register space. Because `shouldSkipSpecialAddress` returns `true` for that address, `checkStorageLimits` never checks whether the EVM storage account's FLOW balance is sufficient to cover the accumulated storage.

EVM gas fees are collected by `runWithGasFeeRefund` in `fvm/evm/handler/handler.go` and transferred to the caller-supplied `gasFeeCollector` EVM address — an EVM-layer address whose balance exists only inside the EVM state trie, not as a FLOW token balance on the EVM storage account. Therefore the EVM storage account's FLOW balance, and hence its storage capacity, does not grow as EVM state grows.

The public entry point is `EVM.run(tx: [UInt8], coinbase: EVMAddress)` declared in `fvm/evm/stdlib/contract.cdc` (line 828). It requires no special entitlement; any Flow transaction signer can call it.

---

### Impact Explanation

An attacker can repeatedly call `EVM.run()` with EVM transactions that maximise state growth (e.g., deploying large contracts, writing many SSTORE slots, creating many new EVM accounts). Each call writes registers to `sc.EVMStorage.Address`. Because the storage limit check is unconditionally skipped for that address, the EVM storage account's `storage.used` grows without bound while its `storage.capacity` (derived from its FLOW balance) remains static. This:

1. **Violates the core Flow protocol invariant** that `storage.used ≤ storage.capacity` for every account.
2. **Allows ledger bloat at below-market cost**: the attacker pays only EVM gas (denominated in attoFLOW and routed to the coinbase), not the FLOW storage reservation that would normally be required to back the same amount of ledger data.
3. **Mirrors the external report's root cause exactly**: state entries are created (EVM storage registers) without the caller being charged the corresponding Flow storage cost, because the accounting step is simply absent for the EVM storage address.

---

### Likelihood Explanation

`EVM.run()` is a public, permissionless function callable from any Flow transaction. No special account key, capability, or admin role is required. The attacker only needs a funded Flow account to pay transaction fees and an EVM account with enough attoFLOW to cover EVM gas. Both are trivially obtainable on mainnet. The attack is repeatable across many transactions and blocks.

---

### Recommendation

Remove the unconditional exemption. Instead, implement one of the following:

1. **Proportional FLOW reservation at EVM state creation time**: when an EVM transaction creates a new account or writes a new storage slot, charge the Flow transaction payer (or a designated EVM storage reserve vault) the equivalent FLOW storage reservation before committing the write.
2. **Periodic rebalancing**: after each EVM block, compute the delta in EVM storage usage and require a corresponding FLOW deposit into the EVM storage account, reverting the block if the deposit is not made.
3. **At minimum**, replace the permanent skip with a bounded exception that enforces a hard cap on the EVM storage account's storage usage until a proper fee model is in place.

---

### Proof of Concept

```cadence
// Any unprivileged Flow transaction can call this.
// The EVM transaction below deploys a contract with 24 KB of bytecode,
// writing ~24 KB of new registers to sc.EVMStorage.Address.
// No FLOW storage reservation is charged; the storage limit check is skipped.

import EVM from <EVMContractAddress>

transaction(rlpTx: [UInt8], coinbaseBytes: [UInt8; 20]) {
    prepare(signer: &Account) {
        let coinbase = EVM.EVMAddress(bytes: coinbaseBytes)
        // EVM.run writes contract bytecode + new account state to
        // sc.EVMStorage.Address registers.
        // TransactionStorageLimiter.shouldSkipSpecialAddress returns true
        // for sc.EVMStorage.Address, so no capacity check is performed.
        let result = EVM.run(tx: rlpTx, coinbase: coinbase)
        // result.status == successful; EVM storage account storage.used
        // has grown, but storage.capacity is unchanged and unchecked.
    }
}
```

Repeating this across many transactions grows `sc.EVMStorage.Address`'s `storage.used` indefinitely. The attacker pays only EVM gas (routed to the coinbase EVM address) and the Flow transaction inclusion fee — never the FLOW storage reservation that the protocol requires for equivalent data written to any other account.

**Relevant code locations:**

- Exemption: [1](#0-0) 
- Skip logic in address collection: [2](#0-1) 
- Public entry point `EVM.run`: [3](#0-2) 
- Gas fees routed to coinbase, not EVM storage account: [4](#0-3)

### Citations

**File:** fvm/transactionStorageLimiter.go (L77-95)
```go
	sc := systemcontracts.SystemContractsForChain(ctx.Chain.ChainID())
	for id := range snapshot.WriteSet {
		address, ok := addressFromRegisterId(id)
		if !ok {
			continue
		}

		if limiter.shouldSkipSpecialAddress(ctx, address, sc) {
			continue
		}

		_, ok = dedup[address]
		if ok {
			continue
		}

		dedup[address] = struct{}{}
		addresses = append(addresses, address)
	}
```

**File:** fvm/transactionStorageLimiter.go (L168-177)
```go
// shouldSkipSpecialAddress returns true if the address is a special address where storage
// limits are not enforced.
// This is currently only the EVM storage address. This is a temporary solution.
func (limiter TransactionStorageLimiter) shouldSkipSpecialAddress(
	ctx Context,
	address flow.Address,
	sc *systemcontracts.SystemContracts,
) bool {
	return sc.EVMStorage.Address == address
}
```

**File:** fvm/evm/stdlib/contract.cdc (L827-836)
```text
    access(all)
    fun run(tx: [UInt8], coinbase: EVMAddress): Result {
        pre {
            !self.isPaused(): "EVM operations are temporarily paused"
        }
        return InternalEVM.run(
            tx: tx,
            coinbase: coinbase.bytes
        ) as! Result
    }
```

**File:** fvm/evm/handler/handler.go (L250-266)
```go
// runWithGasFeeRefund runs a method and transfers the balance changes of the
// coinbase address to the provided gas fee collector
func (h *ContractHandler) runWithGasFeeRefund(gasFeeCollector types.Address, f func()) {
	// capture coinbase init balance
	cb := h.AccountByAddress(types.CoinbaseAddress, true)
	initCoinbaseBalance := cb.Balance()
	f()
	// transfer the gas fees collected to the gas fee collector address
	afterBalance := cb.Balance()
	diff := new(big.Int).Sub(afterBalance, initCoinbaseBalance)
	if diff.Sign() > 0 {
		cb.Transfer(gasFeeCollector, diff)
	}
	if diff.Sign() < 0 { // this should never happen but in case
		panic(fvmErrors.NewEVMError(fmt.Errorf("negative balance change on coinbase")))
	}
}
```
