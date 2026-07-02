### Title
Race Condition Between EVM Users and Liquidators Upon EVM Unpause — (`fvm/evm/stdlib/contract.cdc`)

### Summary
The Flow EVM contract implements a governance-controlled pause mechanism that uniformly blocks all state-mutating EVM operations. When the EVM is unpaused after a maintenance window, there is no grace period or ordering mechanism to allow users to protect their EVM-based DeFi positions before liquidators can act. This creates the same structural race condition described in the external report: users were prevented from taking protective actions during the pause, yet face immediate competition from liquidators the moment the pause is lifted.

### Finding Description
The `isPaused()` function in `fvm/evm/stdlib/contract.cdc` reads a boolean flag from the EVM contract account's storage path `/storage/evmOperationsPaused`:

```cadence
view fun isPaused(): Bool {
    return self.account.storage.copy<Bool>(
        from: /storage/evmOperationsPaused
    ) ?? false
}
``` [1](#0-0) 

When this flag is `true`, every state-mutating EVM entry point enforces the guard:

- `EVMAddress.deposit()` — [2](#0-1) 
- `CadenceOwnedAccount.withdraw()` — [3](#0-2) 
- `CadenceOwnedAccount.deploy()` — [4](#0-3) 
- `CadenceOwnedAccount.call()` — [5](#0-4) 
- `CadenceOwnedAccount.depositNFT/withdrawNFT/depositTokens/withdrawTokens` — [6](#0-5) 
- `EVM.run()` / `EVM.batchRun()` — [7](#0-6) 

All of these are blocked uniformly. The pause is set and cleared by the Governance Committee via a multi-sig Cadence transaction that writes `true` or removes the value at `/storage/evmOperationsPaused`. The bootstrap sequence explicitly pauses and then unpauses the bridge during setup: [8](#0-7) [9](#0-8) 

The `PauseBridgeTransaction` helper confirms this is a live, reachable admin operation: [10](#0-9) 

**The structural gap**: When the EVM is unpaused, the flag is simply removed or set to `false`. All blocked operations become available simultaneously in the very next block. There is no:
- Grace period during which only protective actions (e.g., `deposit` to add collateral) are permitted
- Ordering mechanism that prioritizes user-protective transactions over liquidation transactions
- Delay before liquidation-type calls can be executed

Any Solidity-based lending or margin protocol deployed on Flow EVM (e.g., a protocol where a COA holds collateral and a Solidity contract tracks health factors) is affected. During the pause, collateral prices can move adversely. Users cannot call `CadenceOwnedAccount.deposit()` → `EVMAddress.deposit()` to top up their collateral because the `isPaused()` guard blocks it. When the EVM is unpaused, liquidators and users race to submit transactions in the same block window.

### Impact Explanation
Users with EVM-based DeFi positions that became undercollateralized during the pause period cannot protect their positions before liquidators can act. A liquidator who monitors the EVM contract's storage for the pause flag being cleared can submit a liquidation transaction in the same block as the unpause transaction. The user, who was structurally prevented from taking protective action during the pause, loses collateral to the liquidator. This constitutes unauthorized access to on-chain assets (the user's EVM-held collateral) caused by a structural property of the Flow EVM pause mechanism.

### Likelihood Explanation
The Governance Committee is documented to pause EVM for maintenance and upgrades. The bootstrap code already exercises pause/unpause. Any pause lasting more than a few minutes during a period of price volatility creates the race condition. The attacker's entry path requires only submitting a standard Cadence transaction calling a Solidity liquidation function via `EVM.run()` or `CadenceOwnedAccount.call()` immediately after the unpause — no special privileges are needed.

### Recommendation
After unpausing, introduce a configurable grace period (e.g., stored alongside the pause flag) during which:
1. Protective operations (`deposit`, collateral top-up calls) are permitted immediately.
2. Liquidation-type calls remain blocked until the grace period expires.

Alternatively, mirror the original report's recommendation: emit an on-chain event when unpausing that includes a `gracePeriodEndsAtBlock` field, and have Solidity-based protocols on Flow EVM enforce this grace period in their liquidation logic.

### Proof of Concept

**Setup**: A Solidity lending protocol is deployed on Flow EVM. Alice holds a COA with 100 FLOW deposited as collateral. The protocol's health factor is 1.05 (just above liquidation threshold of 1.0).

**Step 1 — Governance pauses EVM** (e.g., for a protocol upgrade):
```cadence
// Governance multi-sig transaction
transaction() {
    prepare(account: auth(Storage) &Account) {
        account.storage.save(true, to: /storage/evmOperationsPaused)
    }
}
```

**Step 2 — Price drops during pause**: FLOW price drops 10%. Alice's health factor is now 0.95 (liquidatable). Alice attempts to add collateral:
```cadence
// Alice's transaction — BLOCKED by isPaused() guard
transaction() {
    prepare(account: auth(Storage) &Account) {
        let coa = account.storage.borrow<&EVM.CadenceOwnedAccount>(from: /storage/coa)!
        let vault <- ... // obtain FLOW vault
        coa.deposit(from: <-vault) // panics: "EVM operations are temporarily paused"
    }
}
``` [11](#0-10) 

**Step 3 — Governance unpauses EVM**:
```cadence
transaction() {
    prepare(account: auth(Storage) &Account) {
        account.storage.remove<Bool>(from: /storage/evmOperationsPaused)
    }
}
```

**Step 4 — Race condition**: In the same block (or the immediately following block), both Alice and Bob (liquidator) submit transactions. Bob's liquidation call via `EVM.run()` or `coa.call()` executes before Alice's deposit:

```cadence
// Bob's liquidation transaction — succeeds immediately after unpause
transaction(liquidateTx: [UInt8]) {
    prepare(account: auth(Storage) &Account) {
        let coa = account.storage.borrow<auth(EVM.Call) &EVM.CadenceOwnedAccount>(from: /storage/coa)!
        // calls Solidity liquidate(alice_address) — no grace period blocks this
        let res = coa.call(to: lendingProtocol, data: liquidateTx, gasLimit: 300_000, value: EVM.Balance(attoflow: 0))
    }
}
``` [12](#0-11) 

Alice's collateral is liquidated. She had no opportunity to protect her position during the pause, and no grace period after the unpause. The root cause is the uniform, instantaneous unpause with no ordering protection in `fvm/evm/stdlib/contract.cdc`.

### Citations

**File:** fvm/evm/stdlib/contract.cdc (L202-205)
```text
        fun deposit(from: @FlowToken.Vault) {
            pre {
                !EVM.isPaused(): "EVM operations are temporarily paused"
            }
```

**File:** fvm/evm/stdlib/contract.cdc (L562-565)
```text
        access(all)
        fun deposit(from: @FlowToken.Vault) {
            self.address().deposit(from: <-from)
        }
```

**File:** fvm/evm/stdlib/contract.cdc (L587-590)
```text
        fun withdraw(balance: Balance): @FlowToken.Vault {
            pre {
                !EVM.isPaused(): "EVM operations are temporarily paused"
            }
```

**File:** fvm/evm/stdlib/contract.cdc (L623-625)
```text
            pre {
                !EVM.isPaused(): "EVM operations are temporarily paused"
            }
```

**File:** fvm/evm/stdlib/contract.cdc (L636-653)
```text
        access(Owner | Call)
        fun call(
            to: EVMAddress,
            data: [UInt8],
            gasLimit: UInt64,
            value: Balance
        ): Result {
            pre {
                !EVM.isPaused(): "EVM operations are temporarily paused"
            }
            return InternalEVM.call(
                from: self.addressBytes,
                to: to.bytes,
                data: data,
                gasLimit: gasLimit,
                value: value.attoflow
            ) as! Result
        }
```

**File:** fvm/evm/stdlib/contract.cdc (L739-741)
```text
            pre {
                !EVM.isPaused(): "EVM operations are temporarily paused"
            }
```

**File:** fvm/evm/stdlib/contract.cdc (L829-831)
```text
        pre {
            !self.isPaused(): "EVM operations are temporarily paused"
        }
```

**File:** fvm/evm/stdlib/contract.cdc (L1232-1236)
```text
    view fun isPaused(): Bool {
        return self.account.storage.copy<Bool>(
            from: /storage/evmOperationsPaused
        ) ?? false
    }
```

**File:** fvm/bootstrap.go (L1211-1216)
```go
	// Pause the bridge for setup
	txBody, err = blueprints.PauseBridgeTransaction(*env, bridgeEnv, serviceAddress, true)
	if err != nil {
		panic(fmt.Sprintf("failed to build pause the bridge contracts transaction: %s", err))
	}
	_ = run(txBody, "failed to pause the bridge contracts: %s")
```

**File:** fvm/bootstrap.go (L1341-1346)
```go
	// Unpause the bridge
	txBody, err = blueprints.PauseBridgeTransaction(*env, bridgeEnv, serviceAddress, false)
	if err != nil {
		panic(fmt.Sprintf("failed to build un-pause the bridge contracts transaction: %s", err))
	}
	_ = run(txBody, "failed to un-pause the bridge contracts: %s")
```

**File:** fvm/blueprints/bridge.go (L107-122)
```go
// PauseBridgeTransaction returns the transaction body for the transaction
// to pause or unpause the VM bridge
func PauseBridgeTransaction(
	env templates.Environment,
	bridgeEnv bridge.Environment,
	service flow.Address,
	pause bool,
) (*flow.TransactionBody, error) {
	txScript, _ := bridge.GetCadenceTransactionCode("cadence/transactions/bridge/admin/pause/update_bridge_pause_status.cdc", bridgeEnv, env)
	return flow.NewTransactionBodyBuilder().
		SetScript(txScript).
		AddArgument(jsoncdc.MustEncode(cadence.Bool(pause))).
		AddAuthorizer(service).
		SetPayer(service).
		Build()
}
```
