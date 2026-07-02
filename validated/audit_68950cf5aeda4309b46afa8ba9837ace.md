### Title
FLOW Tokens Permanently Locked When Deposited to Special System EVM Addresses - (File: `fvm/evm/stdlib/contract.cdc`)

### Summary
`EVM.EVMAddress.deposit()` is declared `access(all)` and accepts any 20-byte EVM address as the target, including special system addresses (`CoinbaseAddress`, `NativeTokenBridgeAddress`, precompile addresses) that have no Cadence-level withdrawal mechanism. FLOW deposited to these addresses is permanently locked in the EVM environment with no recovery path.

### Finding Description
The `EVM.EVMAddress` struct exposes a `deposit` function that is callable by any unprivileged Cadence transaction or script:

```cadence
access(all)
fun deposit(from: @FlowToken.Vault) {
    ...
    InternalEVM.deposit(from: <-from, to: self.bytes)
    ...
}
``` [1](#0-0) 

This function accepts any `[UInt8; 20]` target address with no validation against reserved system addresses. The special addresses in question are:

- **`NativeTokenBridgeAddress`** = `MakePrecompileAddress(0)` = `{0,0,0,0,0,0,0,0,0,0,0,1,0,0,0,0,0,0,0,0}` — the internal bridge precompile used for deposit/withdraw calls.
- **`CoinbaseAddress`** = `{0,0,0,0,0,0,0,0,0,0,0,3,0,0,0,0,0,0,0,0}` — the intermediate address used for gas fee collection. [2](#0-1) 

The only Cadence-level mechanism to move FLOW back from EVM to Cadence is `InternalEVM.withdraw`, which is invoked exclusively through the `CadenceOwnedAccount.withdraw()` function. That function uses `self.addressBytes` (the COA's own EVM address) as the `from` address:

```cadence
access(Owner | Withdraw)
fun withdraw(balance: Balance): @FlowToken.Vault {
    let vault <- InternalEVM.withdraw(
        from: self.addressBytes,
        amount: balance.attoflow
    ) as! @FlowToken.Vault
``` [3](#0-2) 

At the Go layer, `Account.Withdraw()` requires `isAuthorized = true`, enforced by `executeAndHandleAuthorizedCall`:

```go
func (a *Account) executeAndHandleAuthorizedCall(...) (*types.Result, error) {
    if !a.isAuthorized {
        return nil, types.ErrUnauthorizedMethodCall
    }
    ...
}
``` [4](#0-3) 

The `NativeTokenBridgeAddress` is always accessed with `isAuthorized = false`:

```go
bridge := a.fch.addressAllocator.NativeTokenBridgeAddress()
bridgeAccount := a.fch.AccountByAddress(bridge, false)
``` [5](#0-4) 

Neither `NativeTokenBridgeAddress` nor `CoinbaseAddress` has a corresponding `CadenceOwnedAccount` resource in any Cadence account storage. There is no private key for these addresses to sign EVM transactions. There is no Cadence API path that calls `InternalEVM.withdraw(from: nativeTokenBridgeAddress, ...)` or `InternalEVM.withdraw(from: coinbaseAddress, ...)`.

For `CoinbaseAddress` specifically, the `runWithGasFeeRefund` mechanism only transfers the **difference** (gas fees earned during the transaction) to the `gasFeeCollector`, not any pre-existing balance:

```go
initCoinbaseBalance := cb.Balance()
f()
afterBalance := cb.Balance()
diff := new(big.Int).Sub(afterBalance, initCoinbaseBalance)
if diff.Sign() > 0 {
    cb.Transfer(gasFeeCollector, diff)
}
``` [6](#0-5) 

Any FLOW pre-deposited to `CoinbaseAddress` is absorbed into `initCoinbaseBalance` and is never transferred out.

### Impact Explanation
FLOW tokens deposited to `NativeTokenBridgeAddress` or `CoinbaseAddress` via `EVM.EVMAddress.deposit()` are permanently locked in the EVM state. The Cadence vault is consumed (the FLOW leaves Cadence), the EVM balance at the system address increases, and there is no protocol path to recover those tokens. This constitutes irreversible cross-VM asset loss.

### Likelihood Explanation
Moderate. The `EVM.EVMAddress` struct is a plain value type constructible from any 20-byte array. Any Cadence transaction can construct an `EVMAddress` pointing to `NativeTokenBridgeAddress` or `CoinbaseAddress` and call `deposit`. A user who misreads or is given a malicious address, or a contract author who accidentally targets a system address, will permanently lose their FLOW with no on-chain error or warning. The `deposit` function succeeds silently.

### Recommendation
Add an address validation guard inside `EVM.EVMAddress.deposit()` (and `CadenceOwnedAccount.deposit()`) that panics if the target address falls within any reserved prefix range (`FlowEVMNativePrecompileAddressPrefix`, `FlowEVMExtendedPrecompileAddressPrefix`, or equals `CoinbaseAddress`). Alternatively, expose a Cadence-level recovery function (analogous to OpenZeppelin's `TimelockController.execute` using the contract's own balance) that allows governance to sweep funds from system addresses.

### Proof of Concept
```cadence
import EVM from <EVMContractAddress>
import FlowToken from <FlowTokenAddress>
import FungibleToken from <FungibleTokenAddress>

transaction {
    prepare(signer: auth(BorrowValue) &Account) {
        let vault = signer.storage
            .borrow<auth(FungibleToken.Withdraw) &FlowToken.Vault>(
                from: /storage/flowTokenVault
            )!

        // Withdraw 1 FLOW from Cadence
        let flowVault <- vault.withdraw(amount: 1.0) as! @FlowToken.Vault

        // Deposit to NativeTokenBridgeAddress = 0x00000000000000000000000100000000000000000
        // prefix {0,0,0,0,0,0,0,0,0,0,0,1} + index 0 = all zeros in last 8 bytes
        let nativeBridgeAddr = EVM.EVMAddress(
            bytes: [0,0,0,0,0,0,0,0,0,0,0,1,0,0,0,0,0,0,0,0]
        )

        // Succeeds silently. FLOW is now permanently locked.
        nativeBridgeAddr.deposit(from: <-flowVault)

        // No mechanism exists to recover these tokens.
        // nativeBridgeAddr.balance() will show the deposited amount,
        // but InternalEVM.withdraw(from: nativeBridgeAddr, ...) is
        // unreachable from any Cadence entrypoint.
    }
}
``` [7](#0-6) [1](#0-0)

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

**File:** fvm/evm/stdlib/contract.cdc (L586-606)
```text
        access(Owner | Withdraw)
        fun withdraw(balance: Balance): @FlowToken.Vault {
            pre {
                !EVM.isPaused(): "EVM operations are temporarily paused"
            }

            if balance.isZero() {
                return <-FlowToken.createEmptyVault(vaultType: Type<@FlowToken.Vault>())
            }
            let vault <- InternalEVM.withdraw(
                from: self.addressBytes,
                amount: balance.attoflow
            ) as! @FlowToken.Vault
            emit FLOWTokensWithdrawn(
                address: self.address().toString(),
                amount: balance.inFLOW(),
                withdrawnUUID: vault.uuid,
                balanceAfterInAttoFlow: self.balance().attoflow
            )
            return <-vault
        }
```

**File:** fvm/evm/types/address.go (L31-42)
```go
var (
	// Using leading zeros for prefix helps with the storage compactness.
	//
	// Prefix for the built-in EVM precompiles
	FlowEVMNativePrecompileAddressPrefix = [FlowEVMSpecialAddressPrefixLen]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
	// Prefix for the extended precompiles
	FlowEVMExtendedPrecompileAddressPrefix = [FlowEVMSpecialAddressPrefixLen]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}
	// Prefix for the COA addresses
	FlowEVMCOAAddressPrefix = [FlowEVMSpecialAddressPrefixLen]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2}
	// Coinbase address
	CoinbaseAddress = Address{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3, 0, 0, 0, 0, 0, 0, 0, 0}
)
```

**File:** fvm/evm/handler/handler.go (L252-265)
```go
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
```

**File:** fvm/evm/handler/handler.go (L962-964)
```go
	bridge := a.fch.addressAllocator.NativeTokenBridgeAddress()
	bridgeAccount := a.fch.AccountByAddress(bridge, false)
	// Note: its not an authorized call
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

**File:** fvm/evm/handler/addressAllocator.go (L35-55)
```go
func (aa *AddressAllocator) NativeTokenBridgeAddress() types.Address {
	return MakePrecompileAddress(0)
}

// AllocateCOAAddress allocates an address for COA
func (aa *AddressAllocator) AllocateCOAAddress(uuid uint64) types.Address {
	return MakeCOAAddress(uuid)
}

func MakeCOAAddress(index uint64) types.Address {
	return makePrefixedAddress(mapAddressIndex(index), types.FlowEVMCOAAddressPrefix)
}

func (aa *AddressAllocator) AllocatePrecompileAddress(index uint64) types.Address {
	target := MakePrecompileAddress(index)
	return target
}

func MakePrecompileAddress(index uint64) types.Address {
	return makePrefixedAddress(index, types.FlowEVMExtendedPrecompileAddressPrefix)
}
```
