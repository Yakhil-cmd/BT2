### Title
Delegatecall to Bank Precompile Allows Caller-Identity Spoofing, Enabling Unauthorized Mint/Burn/Transfer of Native CRC20-Backed Tokens — (`x/cronos/keeper/precompiles/bank.go`)

### Summary

The Cronos bank precompile (`BankContract`) derives the native token denom exclusively from `contract.Caller()` for every state-mutating operation (`mint`, `burn`, `transfer`). Under standard go-ethereum EVM semantics, `DELEGATECALL` preserves the parent frame's caller: when an intermediate contract `0xA` (called by `0xCaller`) issues a `delegatecall` to the bank precompile, `contract.Caller()` inside the precompile returns `0xCaller` (the grandparent), not `0xA`. This shifts the denom from `"evm/0xA"` to `"evm/0xCaller"`, allowing the intermediate contract to perform mint/burn/transfer operations on a denom it does not own.

### Finding Description

`BankContract.Run()` derives the token denom on lines 130 and 186:

```go
denom := EVMDenom(contract.Caller())   // line 130 (mint/burn)
denom := EVMDenom(contract.Caller())   // line 186 (transfer)
``` [1](#0-0) [2](#0-1) 

`EVMDenom` simply concatenates the prefix with the hex address:

```go
func EVMDenom(token common.Address) string {
    return EVMDenomPrefix + token.Hex()   // "evm/" + address
}
``` [3](#0-2) 

Under a normal `CALL`:
- `contract.Caller()` = the calling contract `0xA`
- denom = `"evm/0xA"` ✓

Under `DELEGATECALL` from `0xA` (itself called by `0xCaller`):
- `contract.Caller()` = `0xCaller` (grandparent, per EVM spec)
- denom = `"evm/0xCaller"` ✗ — wrong identity

No guard exists anywhere in `Run()` to detect or reject a delegatecall context. The `readonly` flag only blocks `staticcall`; `delegatecall` inherits the parent's non-readonly flag and passes through. [4](#0-3) 

The same pattern applies to the ICA precompile, which derives the ICA `owner` from `contract.Caller()`:

```go
caller := contract.Caller()
owner := sdk.AccAddress(caller.Bytes()).String()
``` [5](#0-4) 

### Impact Explanation

**Critical — Unauthorized mint of native tokens backed by a legitimate CRC20 contract.**

Attack chain:

1. Attacker deploys `0xMalicious` containing a function that issues `delegatecall` to the bank precompile's `mint(attacker, largeAmount)`.
2. A legitimate CRC20 contract `0xLegitCRC20` (which has an admin-registered token mapping for denom `"evm/0xLegitCRC20"`) calls `0xMalicious` through any external-call mechanism (flash-loan callback, hook

### Citations

**File:** x/cronos/keeper/precompiles/bank.go (L56-58)
```go
func EVMDenom(token common.Address) string {
	return EVMDenomPrefix + token.Hex()
}
```

**File:** x/cronos/keeper/precompiles/bank.go (L103-131)
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
```

**File:** x/cronos/keeper/precompiles/bank.go (L186-187)
```go
		denom := EVMDenom(contract.Caller())
		amt := sdk.NewCoin(denom, sdkmath.NewIntFromBigInt(amount))
```

**File:** x/cronos/keeper/precompiles/ica.go (L135-136)
```go
	caller := contract.Caller()
	owner := sdk.AccAddress(caller.Bytes()).String()
```
