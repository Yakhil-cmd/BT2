### Title
Unrestricted `EVMAddress.deposit()` Allows Direct FLOW Deposit to `NativeTokenBridgeAddress`, Permanently Locking Tokens and Inflating `TotalSupply` - (File: `fvm/evm/stdlib/contract.cdc`)

---

### Summary

`EVMAddress.deposit()` in `fvm/evm/stdlib/contract.cdc` is declared `access(all)` with no restriction on the target EVM address. Any unprivileged Cadence transaction can construct an `EVMAddress` struct pointing to the `NativeTokenBridgeAddress` and call `deposit()` on it. This routes FLOW tokens into the bridge transit account via the normal `executeAndHandleCall` path, which increments `bp.TotalSupply` — but the bridge address is not a `CadenceOwnedAccount` and has no `Withdraw` entitlement, so those tokens are permanently irrecoverable. The result is a persistent overstatement of `TotalSupply` relative to the actually-withdrawable EVM balance, weakening the `ErrInsufficientTotalSupply` safety invariant.

---

### Finding Description

`EVMAddress` is a plain Cadence struct whose bytes field can be set to any 20-byte value, including the deterministic `NativeTokenBridgeAddress` allocated by `addressAllocator`. [1](#0-0) 

The function is `access(all)` — no entitlement, no caller check. It calls `InternalEVM.deposit(from: <-from, to: self.bytes)`, which in Go resolves to: [2](#0-1) 

This calls `Account.Deposit()` on the account at `toAddress`. When `toAddress` is the bridge address, `Deposit()` in the handler constructs a `DepositCall` **from bridge to bridge** (a self-transfer): [3](#0-2) 

`executeAndHandleCall` is then called with `totalSupplyDiff = v.Balance()` and `deductSupplyDiff = false`, unconditionally adding the deposited amount to `bp.TotalSupply`: [4](#0-3) 

The bridge address accumulates EVM balance. However, `Withdraw()` requires `isAuthorized = true` (enforced by `executeAndHandleAuthorizedCall`): [5](#0-4) 

The bridge address is never created as an authorized account — it is always obtained with `isAuthorized = false`: [6](#0-5) 

Therefore, any FLOW deposited directly to the bridge address is permanently locked. The Cadence vault is intentionally kept alive (not destroyed) by the deposit implementation: [7](#0-6) 

This means the Cadence-side FLOW tokens are also frozen — they cannot be reclaimed without a protocol upgrade.

---

### Impact Explanation

1. **Permanent token loss**: FLOW tokens deposited to the bridge address are irrecoverable. The Cadence vault is kept alive (not burned), so the tokens are frozen on both sides of the bridge.
2. **`TotalSupply` overstatement**: `bp.TotalSupply` is incremented for each such deposit. Since these tokens can never be withdrawn, `TotalSupply` permanently diverges upward from the actual withdrawable EVM balance. The `ErrInsufficientTotalSupply` guard — the only protocol-level check preventing EVM from issuing more FLOW than was deposited — is silently weakened: [8](#0-7) 

3. **No recovery path**: Unlike a normal misrouted Cadence transfer, there is no admin function or governance mechanism in the handler to drain the bridge address or correct `TotalSupply` without a contract upgrade.

---

### Likelihood Explanation

The attack path requires only a standard unprivileged Cadence transaction. The `NativeTokenBridgeAddress` is deterministic and derivable from public chain configuration. A user can accidentally deposit to it (e.g., by copy-pasting the wrong address), or a malicious actor can do so intentionally to grief the protocol's accounting invariant. No special role, key, or staked node is required.

---

### Recommendation

Add a pre-condition to `EVMAddress.deposit()` that rejects deposits targeting the `NativeTokenBridgeAddress` (and any other reserved system addresses), or restrict the function so that only the `CadenceOwnedAccount.deposit()` wrapper (which targets the COA's own address) is the permitted entry point. Concretely:

```cadence
access(all)
fun deposit(from: @FlowToken.Vault) {
    pre {
        !EVM.isPaused(): "EVM operations are temporarily paused"
        self.bytes != InternalEVM.nativeTokenBridgeAddress():
            "Direct deposit to bridge address is not allowed"
    }
    // ...
}
```

Alternatively, mirror the Liquid Collective fix pattern: introduce a tracked `BridgeDeposit` storage variable that records only deposits made through the authorized `CadenceOwnedAccount` path, and use that variable — rather than raw `TotalSupply` — as the withdrawal ceiling.

---

### Proof of Concept

```cadence
import EVM from <EVM_CONTRACT_ADDRESS>
import FlowToken from <FLOW_TOKEN_ADDRESS>

transaction {
    prepare(signer: auth(BorrowValue) &Account) {
        // Obtain FLOW tokens
        let vault = signer.storage
            .borrow<auth(FungibleToken.Withdraw) &FlowToken.Vault>(
                from: /storage/flowTokenVault)!
            .withdraw(amount: 10.0) as! @FlowToken.Vault

        // Construct EVMAddress pointing at the NativeTokenBridgeAddress
        // (deterministic, publicly derivable from chain config)
        let bridgeAddr = EVM.EVMAddress(
            bytes: [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1] // bridge addr bytes
        )

        // Deposit directly to bridge — access(all) allows this
        bridgeAddr.deposit(from: <-vault)
        // Result:
        //   - 10 FLOW permanently locked in bridge EVM balance
        //   - TotalSupply inflated by 10 FLOW with no corresponding withdrawable COA
    }
}
```

After execution: `EVM.getLatestBlock().totalSupply` is inflated by 10 FLOW, the bridge address holds 10 attoFLOW-equivalent EVM balance, and no `CadenceOwnedAccount` can ever withdraw those tokens. The Cadence vault is also frozen (kept alive per `impl.go` line 671–673).

### Citations

**File:** fvm/evm/stdlib/contract.cdc (L200-223)
```text
        /// Deposits the given vault into the EVM account with the given address
        access(all)
        fun deposit(from: @FlowToken.Vault) {
            pre {
                !EVM.isPaused(): "EVM operations are temporarily paused"
            }

            let amount = from.balance
            if amount == 0.0 {
                destroy from
                return
            }
            let depositedUUID = from.uuid
            InternalEVM.deposit(
                from: <-from,
                to: self.bytes
            )
            emit FLOWTokensDeposited(
                address: self.toString(),
                amount: amount,
                depositedUUID: depositedUUID,
                balanceAfterInAttoFlow: self.balance().attoflow
            )
        }
```

**File:** fvm/evm/impl/impl.go (L670-680)
```go
			// NOTE: We're intentionally not destroying the vault here,
			// because the value of it is supposed to be "kept alive".
			// Destroying would incorrectly be equivalent to a burn and decrease the total supply,
			// and a withdrawal would then have to perform an actual mint of new tokens.

			// Deposit

			const isAuthorized = false
			account := handler.AccountByAddress(toAddress, isAuthorized)
			account.Deposit(types.NewFlowTokenVault(amount))

```

**File:** fvm/evm/handler/handler.go (L820-828)
```go
	if res.Successful() && totalSupplyDiff != nil {
		if deductSupplyDiff {
			bp.TotalSupply = new(big.Int).Sub(bp.TotalSupply, totalSupplyDiff)
			if bp.TotalSupply.Sign() < 0 {
				return nil, types.ErrInsufficientTotalSupply
			}
		} else {
			bp.TotalSupply = new(big.Int).Add(bp.TotalSupply, totalSupplyDiff)
		}
```

**File:** fvm/evm/handler/handler.go (L957-975)
```go
// Deposit deposits the token from the given vault into the flow evm main vault
// and update the account balance with the new amount
func (a *Account) Deposit(v *types.FLOWTokenVault) {
	defer a.fch.backend.StartChildSpan(trace.FVMEVMDeposit).End()

	bridge := a.fch.addressAllocator.NativeTokenBridgeAddress()
	bridgeAccount := a.fch.AccountByAddress(bridge, false)
	// Note: its not an authorized call
	res, err := a.fch.executeAndHandleCall(
		types.NewDepositCall(
			bridge,
			a.address,
			v.Balance(),
			bridgeAccount.Nonce(),
		),
		v.Balance(),
		false,
	)
	panicOnErrorOrInvalidOrFailedState(res, err)
```

**File:** fvm/evm/handler/handler.go (L1062-1070)
```go
func (a *Account) executeAndHandleAuthorizedCall(
	call *types.DirectCall,
	totalSupplyDiff *big.Int,
	deductSupplyDiff bool,
) (*types.Result, error) {
	if !a.isAuthorized {
		return nil, types.ErrUnauthorizedMethodCall
	}
	return a.fch.executeAndHandleCall(call, totalSupplyDiff, deductSupplyDiff)
```
