### Title
Missing Caller Authorization in `BankContract.transfer` Allows Any Contract to Steal Users' Native Bank Tokens - (File: x/cronos/keeper/precompiles/bank.go)

### Summary
The `transfer` method of the bank precompile (`BankContract`) accepts an arbitrary `sender` address from calldata and executes `bankKeeper.SendCoins(from, to, ...)` without verifying that `sender == contract.Caller()`. Any deployed contract can call the bank precompile's `transfer(victimAddr, attackerAddr, amount)` to drain any user's `evm/<contractAddress>` native bank tokens without their consent.

### Finding Description
In `x/cronos/keeper/precompiles/bank.go`, the `TransferMethodName` case unpacks `sender` and `recipient` directly from the ABI-encoded calldata:

```go
sender := args[0].(common.Address)   // arbitrary — from calldata
recipient := args[1].(common.Address) // arbitrary — from calldata
...
from := sdk.AccAddress(sender.Bytes())
to   := sdk.AccAddress(recipient.Bytes())
...
denom := EVMDenom(contract.Caller())  // "evm/<callingContract>"
...
bc.bankKeeper.SendCoins(ctx, from, to, sdk.NewCoins(amt))
```

There is no check that `sender == contract.Caller()`. The denom is scoped to the calling contract (`evm/<callerAddress>`), but the `from` account is fully attacker-controlled. Any contract can therefore move `evm/<itsOwnAddress>` tokens from any victim address to any recipient.

The same flaw exists in the `BurnMethodName` branch: `addr` (the address to burn from) is taken from calldata without verifying it equals `contract.Caller()`, allowing a contract to destroy any user's `evm/<contractAddress>` tokens. [1](#0-0) 

### Impact Explanation
`evm/<contractAddress>` native bank tokens are real, spendable Cosmos-layer assets. Users acquire them by calling `burn` on the bank precompile from a contract (converting ERC20 tokens to native bank tokens), as confirmed by the integration test:

```python
denom = "evm/" + contract.address
tx = contract.functions.moveToNative(amt1).build_transaction(data)
assert_balance(tx, 1, amt1)
```

A malicious contract at address `0xABC` can call `transfer(victimAddr, attackerAddr, amount)` on the bank precompile, causing `bankKeeper.SendCoins` to move the victim's `evm/0xABC` tokens to the attacker. This is an unauthorized, irreversible transfer of user assets — **Critical** impact under the allowed scope (unauthorized transfer of precompile-controlled assets). [2](#0-1) 

### Likelihood Explanation
The bank precompile is registered at address `0x0000...0064` (byte address 100) and is callable by any EVM contract. An attacker only needs to deploy a contract and call the precompile with a crafted `sender` argument. No privileged keys, governance access, or leaked secrets are required. Any user who holds `evm/<contractAddress>` native bank tokens is at risk from the contract at that address. [3](#0-2) 

### Recommendation
Add a caller-authorization check at the top of the `TransferMethodName` case:

```go
if sender != contract.Caller() {
    return nil, errors.New("transfer: sender must be the calling contract")
}
```

Similarly, for the `BurnMethodName` branch, verify that `recipient == contract.Caller()` (i.e., a contract may only burn its own tokens, not another user's). [4](#0-3) 

### Proof of Concept

1. Victim calls `MaliciousContract.moveToNative(100)` → contract calls bank precompile `burn(victimAddr, 100)` → victim now holds 100 `evm/0xMaliciousContract` native bank tokens.

2. Attacker calls `MaliciousContract.steal(victimAddr, attackerAddr, 100)`, which internally calls:
   ```solidity
   IBankModule(0x0000...0064).transfer(victimAddr, attackerAddr, 100);
   ```

3. Bank precompile executes:
   ```go
   denom := EVMDenom(contract.Caller()) // "evm/0xMaliciousContract"
   bc.bankKeeper.SendCoins(ctx, victimAddr, attackerAddr, [{denom, 100}])
   ```
   No authorization check is performed. The victim's 100 `evm/0xMaliciousContract` tokens are transferred to the attacker. [5](#0-4)

### Citations

**File:** x/cronos/keeper/precompiles/bank.go (L30-33)
```go
var (
	bankABI                 abi.ABI
	bankContractAddress     = common.BytesToAddress([]byte{100})
	bankGasRequiredByMethod = map[[4]byte]uint64{}
```

**File:** x/cronos/keeper/precompiles/bank.go (L103-200)
```go
func (bc *BankContract) Run(evm *vm.EVM, contract *vm.Contract, readonly bool) ([]byte, error) {
	// parse input
	methodID := contract.Input[:4]
	method, err := bankABI.MethodById(methodID)
	if err != nil {
		return nil, err
	}
	stateDB := evm.StateDB.(ExtStateDB)
	precompileAddr := bc.Address()
	switch method.Name {
	case MintMethodName, BurnMethodName:
		if readonly {
			return nil, errors.New("the method is not readonly")
		}
		args, err := method.Inputs.Unpack(contract.Input[4:])
		if err != nil {
			return nil, errors.New("fail to unpack input arguments")
		}
		recipient := args[0].(common.Address)
		amount := args[1].(*big.Int)
		if amount.Sign() <= 0 {
			return nil, errors.New("invalid amount")
		}
		addr := sdk.AccAddress(recipient.Bytes())
		if err := bc.checkBlockedAddr(addr); err != nil {
			return nil, err
		}
		denom := EVMDenom(contract.Caller())
		amt := sdk.NewCoin(denom, sdkmath.NewIntFromBigInt(amount))
		err = stateDB.ExecuteNativeAction(precompileAddr, nil, func(ctx sdk.Context) error {
			if err := bc.bankKeeper.IsSendEnabledCoins(ctx, amt); err != nil {
				return err
			}
			if method.Name == "mint" {
				if err := bc.bankKeeper.MintCoins(ctx, types.ModuleName, sdk.NewCoins(amt)); err != nil {
					return errorsmod.Wrap(err, "fail to mint coins in precompiled contract")
				}
				if err := bc.bankKeeper.SendCoinsFromModuleToAccount(ctx, types.ModuleName, addr, sdk.NewCoins(amt)); err != nil {
					return errorsmod.Wrap(err, "fail to send mint coins to account")
				}
			} else {
				if err := bc.bankKeeper.SendCoinsFromAccountToModule(ctx, addr, types.ModuleName, sdk.NewCoins(amt)); err != nil {
					return errorsmod.Wrap(err, "fail to send burn coins to module")
				}
				if err := bc.bankKeeper.BurnCoins(ctx, types.ModuleName, sdk.NewCoins(amt)); err != nil {
					return errorsmod.Wrap(err, "fail to burn coins in precompiled contract")
				}
			}
			return nil
		})
		if err != nil {
			return nil, err
		}
		return method.Outputs.Pack(true)
	case BalanceOfMethodName:
		args, err := method.Inputs.Unpack(contract.Input[4:])
		if err != nil {
			return nil, errors.New("fail to unpack input arguments")
		}
		token := args[0].(common.Address)
		addr := args[1].(common.Address)
		// query from storage
		balance := bc.bankKeeper.GetBalance(stateDB.Context(), sdk.AccAddress(addr.Bytes()), EVMDenom(token)).Amount.BigInt()
		return method.Outputs.Pack(balance)
	case TransferMethodName:
		if readonly {
			return nil, errors.New("the method is not readonly")
		}
		args, err := method.Inputs.Unpack(contract.Input[4:])
		if err != nil {
			return nil, errors.New("fail to unpack input arguments")
		}
		sender := args[0].(common.Address)
		recipient := args[1].(common.Address)
		amount := args[2].(*big.Int)
		if amount.Sign() <= 0 {
			return nil, errors.New("invalid amount")
		}
		from := sdk.AccAddress(sender.Bytes())
		to := sdk.AccAddress(recipient.Bytes())
		if err := bc.checkBlockedAddr(to); err != nil {
			return nil, err
		}
		denom := EVMDenom(contract.Caller())
		amt := sdk.NewCoin(denom, sdkmath.NewIntFromBigInt(amount))
		err = stateDB.ExecuteNativeAction(precompileAddr, nil, func(ctx sdk.Context) error {
			if err := bc.bankKeeper.IsSendEnabledCoins(ctx, amt); err != nil {
				return err
			}
			if err := bc.bankKeeper.SendCoins(ctx, from, to, sdk.NewCoins(amt)); err != nil {
				return errorsmod.Wrap(err, "fail to send coins in precompiled contract")
			}
			return nil
		})
		if err != nil {
			return nil, err
		}
		return method.Outputs.Pack(true)
```
