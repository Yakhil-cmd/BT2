### Title
Single Pause Flag Blocks Withdrawals While Unpausing Re-Enables Deposits - (File: fvm/evm/stdlib/contract.cdc)

### Summary
The `EVM` contract uses a single boolean flag (`/storage/evmOperationsPaused`) to pause all EVM operations uniformly. When the Governance Committee pauses EVM for an emergency, users cannot withdraw their FLOW tokens from EVM. To allow withdrawals, the Governance Committee must remove the pause, but this simultaneously re-enables deposits via the `access(all)` `EVMAddress.deposit()` function, defeating the purpose of the emergency pause.

### Finding Description
`EVM.isPaused()` reads a single `Bool` from `/storage/evmOperationsPaused` and applies it uniformly to every state-mutating EVM operation. [1](#0-0) 

All deposit and withdrawal paths check this same flag:

- `EVMAddress.deposit()` checks `!EVM.isPaused()` [2](#0-1) 
- `CadenceOwnedAccount.withdraw()` checks `!EVM.isPaused()` [3](#0-2) 
- `CadenceOwnedAccount.deposit()` delegates to `self.address().deposit()`, which also checks `!EVM.isPaused()` [4](#0-3) 

There is no granular pause: deposits and withdrawals share the same gate. When the flag is set, users cannot withdraw their FLOW tokens out of EVM. When the flag is cleared to allow withdrawals, `EVMAddress.deposit()` — which is `access(all)` and callable by any unprivileged transaction sender — is simultaneously re-enabled.

### Impact Explanation
**Impact: High.** When EVM is paused for an emergency (e.g., to halt a drain or a bridge exploit), all FLOW tokens held in EVM accounts become inaccessible to their owners. The Governance Committee is forced to unpause to allow user withdrawals. The moment the pause is lifted, any unprivileged user can call `EVMAddress.deposit()` to deposit new FLOW into EVM, re-exposing funds to whatever condition triggered the emergency pause and preventing the pause from achieving its intended protective effect. Assets already in EVM remain at risk.

### Likelihood Explanation
**Likelihood: Medium.** Emergency pauses are not routine operations, but they are a critical safety mechanism. The Governance Committee's only recourse — unpausing — is guaranteed to re-enable deposits. Any user monitoring the chain can immediately deposit after the unpause, making exploitation trivially easy once the precondition (a governance pause) is met.

### Recommendation
Introduce separate pause granularity for deposits and withdrawals. For example, store two independent flags (e.g., `/storage/evmDepositsPaused` and `/storage/evmWithdrawalsPaused`) and check the appropriate flag in each function. This allows the Governance Committee to block new deposits while keeping withdrawals open during an emergency, mirroring the recommendation in the original report.

### Proof of Concept
1. Governance Committee saves `true` to `/storage/evmOperationsPaused` on the EVM contract account (as demonstrated in the test setup at line 6384). [5](#0-4) 

2. All EVM operations are now blocked. Users holding FLOW in EVM COA accounts cannot call `CadenceOwnedAccount.withdraw()` — it panics with `"EVM operations are temporarily paused"`. [3](#0-2) 

3. To allow users to recover their funds, the Governance Committee removes the flag (sets it to `false` or removes the storage value).

4. Immediately after, any unprivileged user submits a transaction calling:
   ```cadence
   let address = EVM.EVMAddress(bytes: victimAddr)
   address.deposit(from: <-vault)
   ```
   This succeeds because `EVMAddress.deposit()` is `access(all)` and the pause flag is now cleared. [6](#0-5) 

5. New FLOW tokens are now deposited into EVM while the emergency condition may still be active, defeating the purpose of the pause and potentially re-exposing funds to the original threat.

### Citations

**File:** fvm/evm/stdlib/contract.cdc (L201-205)
```text
        access(all)
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

**File:** fvm/evm/stdlib/contract.cdc (L1232-1236)
```text
    view fun isPaused(): Bool {
        return self.account.storage.copy<Bool>(
            from: /storage/evmOperationsPaused
        ) ?? false
    }
```

**File:** fvm/evm/evm_test.go (L6382-6385)
```go
			prepare(account: auth(Storage) &Account) {
				account.storage.save(<- EVM.createCadenceOwnedAccount(), to: /storage/coa)
				account.storage.save(true, to: /storage/evmOperationsPaused)
			}
```
