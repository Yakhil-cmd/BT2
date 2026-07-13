### Title
Unauthorized Transfer of Any User's Native Bank Tokens via Missing Caller Authorization in Bank Precompile `transfer` Method - (File: `x/cronos/keeper/precompiles/bank.go`)

### Summary
The bank precompile's `transfer` method accepts an arbitrary `sender` address as a caller-supplied ABI argument and executes `bankKeeper.SendCoins(ctx, from, to, ...)` without verifying that `sender == contract.Caller()`. Any EVM contract can therefore drain native tokens of its own denom (`evm/<contractAddress>`) from any user's account without that user's consent or approval.

### Finding Description
In `BankContract.Run()`, the `TransferMethodName` case unpacks three arguments from the call input: `sender`, `recipient`, and `amount`. The denom is correctly scoped to `EVMDenom(contract.Caller())` — i.e., only the calling contract's own denom can be moved. However, the `from` address passed to `bankKeeper.SendCoins` is taken directly from `args[0]` (the caller-supplied `sender`), with no check that `sender == contract.Caller()` or that the sender has granted any allowance to the calling contract.

```go
// x/cronos/keeper/precompiles/bank.go  lines 175–192
sender := args[0].(common.Address)   // ← fully attacker-controlled
recipient := args[1].(common.Address)
...
from := sdk.AccAddress(sender.Bytes())
to   := sdk.AccAddress(recipient.Bytes())
...
denom := EVMDenom(contract.Caller()) // denom scoped to caller, but source address is not
...
bc.bankKeeper.SendCoins(ctx, from, to, sdk.NewCoins(amt))
```

The same pattern exists for `burn`: `args[0]` is the address whose tokens are burned, again with no check that it equals `contract.Caller()`. [1](#0-0) 

Compare this to the `exec` helper used by other precompiles, which explicitly enforces `caller == signer`:

```go
// x/cronos/keeper/precompiles/utils.go  lines 46–48
caller := common.BytesToAddress(signers[0])
if caller != e.caller {
    return nil, fmt.Errorf("caller is not authenticated: ...")
}
``` [2](#0-1) 

The bank precompile has no equivalent guard.

### Impact Explanation
**Critical — Unauthorized transfer of precompile-controlled assets.**

`evm/<contractAddress>` tokens are native Cosmos bank module tokens managed exclusively through the bank precompile. A user acquires them by calling a contract function that invokes `bank.mint(userAddress, amount)` (e.g., `moveToNative` in `TestBank.sol`). Once a user holds a balance of `evm/0xAttackerContract`, the attacker contract can call:

```solidity
bank.transfer(victimAddress, attackerAddress, victimBalance);
```

This executes `bankKeeper.SendCoins(ctx, victim, attacker, coins)` with no authorization check, transferring the victim's entire native token balance to the attacker. The attacker can then call `bank.burn(attackerAddress, amount)` to convert back to ERC-20 form, or bridge out. [3](#0-2) 

### Likelihood Explanation
Medium. The attacker must first induce users to hold native tokens of the attacker's contract denom. This is achievable through a legitimate-looking DeFi contract that offers `moveToNative`-style functionality, yield farming, or any protocol that calls `bank.mint` on behalf of users. Once users hold the denom, the drain is a single contract call with no further preconditions.

### Recommendation
Add a caller-authorization check in the `TransferMethodName` case before executing `SendCoins`. The `sender` argument must equal `contract.Caller()`:

```go
if sender != contract.Caller() {
    return nil, errors.New("transfer: sender must be the calling contract")
}
```

Apply the same fix to `BurnMethodName`: verify `recipient == contract.Caller()` before burning. Alternatively, adopt the `exec` pattern from `utils.go` which already enforces signer-equals-caller.

### Proof of Concept

1. Attacker deploys `DrainContract` at address `0xDRAIN`. The contract exposes:
   - `deposit()`: calls `bank.mint(msg.sender, amount)` — users receive `evm/0xDRAIN` native tokens.
   - `drain(address victim, uint256 amount)`: calls `bank.transfer(victim, attacker, amount)`.

2. Users call `deposit()`, acquiring `evm/0xDRAIN` native bank tokens.

3. Attacker calls `drain(victimAddress, victimBalance)` from `DrainContract`.

4. The bank precompile executes:
   ```go
   from  = sdk.AccAddress(victimAddress.Bytes())
   to    = sdk.AccAddress(attackerAddress.Bytes())
   denom = "evm/0xDRAIN"
   bankKeeper.SendCoins(ctx, from, to, coins)  // no auth check
   ```

5. All `evm/0xDRAIN` tokens are transferred from victim to attacker. The attacker can repeat for every holder. [4](#0-3) [5](#0-4)

### Citations

**File:** x/cronos/keeper/precompiles/bank.go (L56-58)
```go
func EVMDenom(token common.Address) string {
	return EVMDenomPrefix + token.Hex()
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

**File:** x/cronos/keeper/precompiles/utils.go (L46-49)
```go
	caller := common.BytesToAddress(signers[0])
	if caller != e.caller {
		return nil, fmt.Errorf("caller is not authenticated: expected %s, got %s", e.caller.Hex(), caller.Hex())
	}
```
