### Title
Missing On-Chain `pause()`/`unpause()` Functions in EVM Contract Despite `isPaused()` Guards on All Critical Functions - (File: `fvm/evm/stdlib/contract.cdc`)

---

### Summary

The `EVM` Cadence contract guards every state-mutating entry point with `!EVM.isPaused()` pre-conditions, but the contract itself exposes no `pause()` or `unpause()` function. The pause flag is read from `/storage/evmOperationsPaused` in the service account's storage, yet no contract-level function writes to that path. This is a structural analog to the reported Solidity finding: pause checks exist, but the activation mechanism is absent from the contract interface.

---

### Finding Description

`EVM.isPaused()` is defined as:

```cadence
access(all)
view fun isPaused(): Bool {
    return self.account.storage.copy<Bool>(
        from: /storage/evmOperationsPaused
    ) ?? false
}
``` [1](#0-0) 

This flag gates every critical state-mutating function in the contract:

- `CadenceOwnedAccount.withdraw()` [2](#0-1) 
- `CadenceOwnedAccount.deploy()` [3](#0-2) 
- `CadenceOwnedAccount.call()` [4](#0-3) 
- `CadenceOwnedAccount.callWithSigAndArgs()` [5](#0-4) 
- `CadenceOwnedAccount.depositNFT()` [6](#0-5) 
- `CadenceOwnedAccount.withdrawNFT()` [7](#0-6) 
- `CadenceOwnedAccount.depositTokens()` [8](#0-7) 
- `CadenceOwnedAccount.withdrawTokens()` [9](#0-8) 
- `EVM.createCadenceOwnedAccount()` [10](#0-9) 
- `EVM.run()` [11](#0-10) 
- `EVM.batchRun()` [12](#0-11) 

Searching the entire contract, there is **no `pause()` or `unpause()` function** anywhere in `contract.cdc`. The contract `init()` does not write to `/storage/evmOperationsPaused` either. [13](#0-12) 

The contract comment acknowledges this design:

> "Only the Governance Committee can pause the EVM transactions, with a multi-sig Cadence transaction." [14](#0-13) 

The only demonstrated mechanism to set the pause flag is a raw storage write transaction, as shown in the test harness:

```cadence
account.storage.save(true, to: /storage/evmOperationsPaused)
``` [15](#0-14) 

This is not a contract function — it is a privileged raw storage mutation that must be crafted and submitted as a bespoke transaction.

---

### Impact Explanation

The `EVM` contract is the sole on-chain gateway for all Cadence↔EVM interactions including FLOW token bridging, NFT bridging, fungible token bridging, COA creation, and raw EVM transaction execution. All of these paths move real on-chain assets.

If a critical vulnerability is discovered and actively exploited in EVM execution (e.g., a bridge escrow accounting error, an `InternalEVM` bug allowing unauthorized minting or draining), the Governance Committee cannot invoke a `pause()` function on the contract. They must instead:

1. Identify the correct raw storage path (`/storage/evmOperationsPaused`),
2. Craft a bespoke Cadence transaction that writes `true` as a `Bool` to that exact path,
3. Coordinate multi-sig authorization on the service account,
4. Submit and execute it.

This is materially slower and more error-prone than calling a named `pause()` function. During the delay, the exploit continues. The result is potential **cross-VM asset loss** — FLOW tokens and bridged assets can be drained from the EVM bridge escrow while the pause mechanism remains unactivated.

Additionally, `isPaused()` uses `copy<Bool>` with a `?? false` fallback. If the storage path holds a value of a different type (e.g., a `String` or `UInt8`), `copy<Bool>` returns `nil`, `isPaused()` returns `false`, and all guards silently pass — meaning a malformed storage write could permanently disable the pause mechanism. [16](#0-15) 

---

### Likelihood Explanation

The pause mechanism is explicitly designed for emergency use. The absence of a `pause()` function means every emergency response requires a bespoke raw transaction rather than a standard contract call. Given that the EVM bridge handles real FLOW and bridged asset flows, the probability that an emergency requiring a pause will occur is non-trivial. The structural gap is present in every deployment of this contract version.

---

### Recommendation

Add access-controlled `pause()` and `unpause()` functions to the `EVM` contract that write to `/storage/evmOperationsPaused`, restricted to the contract account (e.g., `access(account)`):

```cadence
access(account)
fun pause() {
    if self.account.storage.type(at: /storage/evmOperationsPaused) != nil {
        self.account.storage.load<Bool>(from: /storage/evmOperationsPaused)
    }
    self.account.storage.save(true, to: /storage/evmOperationsPaused)
}

access(account)
fun unpause() {
    self.account.storage.load<Bool>(from: /storage/evmOperationsPaused)
}
```

This makes the pause mechanism discoverable, auditable, and callable through the standard contract interface, matching the intent of the `isPaused()` guards already present on all critical functions.

---

### Proof of Concept

**Step 1 — Confirm no `pause()` function exists in the contract:**

Search `fvm/evm/stdlib/contract.cdc` for any function that writes to `/storage/evmOperationsPaused`. Result: none. The only write is in the test file `fvm/evm/evm_test.go` line 6384, performed as a raw storage save by the service account. [17](#0-16) 

**Step 2 — Confirm all critical functions are guarded:**

Every state-mutating EVM function contains `pre { !EVM.isPaused(): "EVM operations are temporarily paused" }`. [11](#0-10) 

**Step 3 — Confirm the pause flag is never initialized:**

The `init()` function only calls `setupHeartbeat()` and does not write to `/storage/evmOperationsPaused`. [13](#0-12) 

**Step 4 — Demonstrate the gap:**

An attacker exploiting a critical EVM execution bug (e.g., a bridge accounting error) submits repeated `EVM.run()` or `CadenceOwnedAccount.withdraw()` transactions. The Governance Committee cannot call `EVM.pause()` — no such function exists. They must craft a raw storage write transaction, coordinate multi-sig, and submit it. During this window, the exploit continues and on-chain assets are lost.

### Citations

**File:** fvm/evm/stdlib/contract.cdc (L587-590)
```text
        fun withdraw(balance: Balance): @FlowToken.Vault {
            pre {
                !EVM.isPaused(): "EVM operations are temporarily paused"
            }
```

**File:** fvm/evm/stdlib/contract.cdc (L622-625)
```text
        ): Result {
            pre {
                !EVM.isPaused(): "EVM operations are temporarily paused"
            }
```

**File:** fvm/evm/stdlib/contract.cdc (L642-645)
```text
        ): Result {
            pre {
                !EVM.isPaused(): "EVM operations are temporarily paused"
            }
```

**File:** fvm/evm/stdlib/contract.cdc (L668-671)
```text
        ): ResultDecoded {
            pre {
                !EVM.isPaused(): "EVM operations are temporarily paused"
            }
```

**File:** fvm/evm/stdlib/contract.cdc (L738-741)
```text
        ) {
            pre {
                !EVM.isPaused(): "EVM operations are temporarily paused"
            }
```

**File:** fvm/evm/stdlib/contract.cdc (L760-763)
```text
        ): @{NonFungibleToken.NFT} {
            pre {
                !EVM.isPaused(): "EVM operations are temporarily paused"
            }
```

**File:** fvm/evm/stdlib/contract.cdc (L777-780)
```text
        ) {
            pre {
                !EVM.isPaused(): "EVM operations are temporarily paused"
            }
```

**File:** fvm/evm/stdlib/contract.cdc (L792-795)
```text
        ): @{FungibleToken.Vault} {
            pre {
                !EVM.isPaused(): "EVM operations are temporarily paused"
            }
```

**File:** fvm/evm/stdlib/contract.cdc (L807-810)
```text
    fun createCadenceOwnedAccount(): @CadenceOwnedAccount {
        pre {
            !self.isPaused(): "EVM operations are temporarily paused"
        }
```

**File:** fvm/evm/stdlib/contract.cdc (L828-831)
```text
    fun run(tx: [UInt8], coinbase: EVMAddress): Result {
        pre {
            !self.isPaused(): "EVM operations are temporarily paused"
        }
```

**File:** fvm/evm/stdlib/contract.cdc (L918-921)
```text
    fun batchRun(txs: [[UInt8]], coinbase: EVMAddress): [Result] {
        pre {
            !self.isPaused(): "EVM operations are temporarily paused"
        }
```

**File:** fvm/evm/stdlib/contract.cdc (L1223-1236)
```text
    /// Returns whether EVM transactions have been paused, either for
    /// maintenance or any situation that requires special governance
    /// handling.
    ///
    /// Only the Governance Committee can pause the EVM transactions, with
    /// a multi-sig Cadence transaction. The EVM enters a read-only mode,
    /// where all EVM state is available for reading, but no state updates
    /// are executed.
    access(all)
    view fun isPaused(): Bool {
        return self.account.storage.copy<Bool>(
            from: /storage/evmOperationsPaused
        ) ?? false
    }
```

**File:** fvm/evm/stdlib/contract.cdc (L1238-1240)
```text
    init() {
        self.setupHeartbeat()
    }
```

**File:** fvm/evm/evm_test.go (L6377-6395)
```go
	code := fmt.Appendf(nil,
		`
		import EVM from %s

		transaction(){
			prepare(account: auth(Storage) &Account) {
				account.storage.save(<- EVM.createCadenceOwnedAccount(), to: /storage/coa)
				account.storage.save(true, to: /storage/evmOperationsPaused)
			}
		}
		`,
		sc.EVMContract.Address.HexWithPrefix(),
	)

	txBody, err := flow.NewTransactionBodyBuilder().
		SetScript(code).
		SetPayer(sc.FlowServiceAccount.Address).
		AddAuthorizer(sc.FlowServiceAccount.Address).
		Build()
```
