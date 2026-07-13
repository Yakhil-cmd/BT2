### Title
Bank Precompile `transfer` Method Allows Unauthorized Transfer of `evm/` Denom Tokens Without Sender Authorization - (File: x/cronos/keeper/precompiles/bank.go)

### Summary
The `transfer` method in the bank precompile accepts a `sender` address from calldata but never validates that it matches `contract.Caller()`. Any EVM contract can therefore call `bank.transfer(victim, attacker, amount)` and move `evm/<contract>` native tokens out of any holder's account without the holder's consent.

### Finding Description
In `x/cronos/keeper/precompiles/bank.go`, the `TransferMethodName` case unpacks three arguments from calldata — `sender`, `recipient`, and `amount` — and executes `bankKeeper.SendCoins(ctx, from, to, coins)` where `from = sdk.AccAddress(sender.Bytes())`.

The denom is correctly bound to the calling contract via `denom := EVMDenom(contract.Caller())`, but the `sender` field is taken verbatim from the ABI-encoded input with no check that `sender == contract.Caller()`:

```go
sender := args[0].(common.Address)          // from calldata — attacker-controlled
recipient := args[1].(common.Address)
amount := args[2].(*big.Int)
from := sdk.AccAddress(sender.Bytes())
to   := sdk.AccAddress(recipient.Bytes())
denom := EVMDenom(contract.Caller())        // denom tied to caller ✓
// ← no check: sender == contract.Caller()
bc.bankKeeper.SendCoins(ctx, from, to, sdk.NewCoins(amt))
```

The same structural omission exists in the `BurnMethodName` branch, where `addr` (the account to burn from) is taken from calldata without verifying it equals the caller.

This is the direct Cronos analog of the external M-02 finding: in that report, gas-refund parameters (`safeTxGas`, `baseGas`, `gasPrice`, `gasToken`, `refundReceiver`) were excluded from the trusted-validator signature, letting an operator manipulate them to drain funds. Here, the `sender` parameter is excluded from any caller-identity check, letting a contract drain `evm/` tokens from arbitrary holders.

### Impact Explanation
**Critical — Unauthorized transfer of CRC20/EVM-denom assets.**

Any contract that holds the `evm/<contract>` denom mapping can call `bank.transfer(victim, self, victim_balance)` and atomically move the victim's entire native `evm/` token balance to itself. Because the bank precompile executes inside `stateDB.ExecuteNativeAction`, the transfer is committed as part of the EVM transaction with no additional authorization gate. Affected assets are native Cosmos-side `evm/` denom tokens, which users acquire by calling `moveToNative` or by receiving them from other accounts.

### Likelihood Explanation
Any unprivileged EVM contract can reach this code path by calling precompile address `0x0000…0064` with the `transfer` selector. No special role, governance action, or leaked key is required. The only precondition is that some account holds a non-zero balance of `evm/<attacker_contract>` tokens, which is a normal outcome of interacting with any CRC20-style contract that uses the bank precompile.

### Recommendation
Add a caller-identity guard in the `TransferMethodName` case (and symmetrically in `BurnMethodName`) before executing the bank send:

```go
if sender != contract.Caller() {
    return nil, errors.New("sender must be the calling contract")
}
```

Alternatively, remove the `sender` argument entirely and derive it from `contract.Caller()`, mirroring how `denom` is already derived. This matches the pattern used in `utils.go`'s `exec` helper, which explicitly checks `caller != e.caller` before dispatching any IBC message.

### Proof of Concept

1. Victim calls `bank.mint(victim_addr, 1000)` on `MaliciousContract`, receiving 1000 `evm/MaliciousContract` native tokens.
2. Attacker deploys `MaliciousContract` with a function:
   ```solidity
   function steal(address victim, address attacker, uint256 amount) external {
       IBankPrecompile(0x0000...0064).transfer(victim, attacker, amount);
   }
   ```
3. Attacker calls `steal(victim_addr, attacker_addr, 1000)`.
4. The bank precompile executes `bankKeeper.SendCoins(victim_addr, attacker_addr, [1000 evm/MaliciousContract])` with no authorization check on `victim_addr`.
5. Victim's 1000 `evm/MaliciousContract` tokens are transferred to the attacker in a single transaction.

Relevant code locations: [1](#0-0) [2](#0-1) [3](#0-2)

### Citations

**File:** x/cronos/keeper/precompiles/bank.go (L113-155)
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

**File:** x/cronos/keeper/precompiles/utils.go (L38-49)
```go
	signers, _, err := e.cdc.GetMsgV1Signers(msg)
	if err != nil {
		return nil, fmt.Errorf("fail to get signers %w", err)
	}

	if len(signers) != 1 {
		return nil, errors.New("don't support multi-signers message")
	}
	caller := common.BytesToAddress(signers[0])
	if caller != e.caller {
		return nil, fmt.Errorf("caller is not authenticated: expected %s, got %s", e.caller.Hex(), caller.Hex())
	}
```
