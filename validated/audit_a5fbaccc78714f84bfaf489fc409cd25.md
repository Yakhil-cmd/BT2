### Title
Unauthorized Native Token Transfer via Missing Sender Authorization in Bank Precompile `transfer` Method - (File: `x/cronos/keeper/precompiles/bank.go`)

### Summary

The `BankContract.Run()` precompile in `x/cronos/keeper/precompiles/bank.go` handles a `transfer(address sender, address recipient, uint256 amount)` method that accepts the `sender` address as a caller-supplied argument. There is no check that `sender == contract.Caller()`. Any EVM contract can therefore transfer `evm/<itsOwnAddress>` native tokens out of any account that holds them, without that account's authorization.

### Finding Description

The bank precompile at address `0x64` exposes four methods: `mint`, `burn`, `balanceOf`, and `transfer`. The denom operated on is always `EVMDenom(contract.Caller())` = `"evm/" + callerContractAddress`. For `mint` and `burn`, the target address is taken from `args[0]` but those operations are bounded to the caller's own denom namespace. For `transfer`, however, the `from` address is taken directly from `args[0]` (the `sender` argument) and is passed verbatim to `bankKeeper.SendCoins(ctx, from, to, ...)`:

```go
// x/cronos/keeper/precompiles/bank.go lines 175-192
sender := args[0].(common.Address)   // ← fully attacker-controlled
recipient := args[1].(common.Address)
...
from := sdk.AccAddress(sender.Bytes())
to   := sdk.AccAddress(recipient.Bytes())
...
denom := EVMDenom(contract.Caller())  // "evm/0xATTACKER"
...
bc.bankKeeper.SendCoins(ctx, from, to, sdk.NewCoins(amt))
```

There is no guard of the form `sender == contract.Caller()`. The only check performed is `checkBlockedAddr(to)`, which only prevents sending to module-blocked addresses.

Compare this with the `exec()` helper used by the relayer and ICA precompiles, which explicitly enforces `caller == signer`:

```go
// x/cronos/keeper/precompiles/utils.go lines 46-48
caller := common.BytesToAddress(signers[0])
if caller != e.caller {
    return nil, fmt.Errorf("caller is not authenticated: ...")
}
```

No equivalent guard exists in the bank precompile's `transfer` path.

### Impact Explanation

**Critical — Unauthorized transfer of native `evm/` denom tokens.**

A user who holds `evm/0xATTACKER` native tokens (acquired by calling `moveToNative` or equivalent on the attacker's contract, which burns ERC20 tokens and calls `bank.mint`) can have those tokens drained at any time by the attacker calling `bank.transfer(victim, attacker, victimBalance)` from their contract. The victim's native tokens are transferred without consent. Because `evm/` denom tokens represent real value (they are the native-layer equivalent of ERC20 tokens that were burned to create them), this constitutes an unauthorized balance change for native assets.

### Likelihood Explanation

The attacker must control an EVM contract and must have induced victims to hold `evm/<attackerContract>` tokens. This is achievable by deploying a DeFi contract that uses the bank precompile for ERC20↔native conversion. Any user who calls `moveToNative` on such a contract is immediately at risk. The attack requires no special permissions, no leaked keys, and no governance action — only a deployed EVM contract.

### Recommendation

In the `TransferMethodName` case, verify that the `sender` argument equals `contract.Caller()`:

```go
if sender != contract.Caller() {
    return nil, errors.New("sender is not authenticated")
}
```

This mirrors the authorization pattern already used in `exec()` for the relayer and ICA precompiles.

### Proof of Concept

1. Attacker deploys `MaliciousContract` at `0xMAL` with two functions:
   - `depositFor(address victim, uint256 amount)`: calls `bank.mint(victim, amount)` after burning ERC20 tokens from `msg.sender` — this mints `evm/0xMAL` native tokens to `victim`
   - `drain(address victim, uint256 amount)`: calls `bank.transfer(victim, attacker, amount)` — this transfers `evm/0xMAL` tokens from `victim` to `attacker`
2. Victim calls `depositFor(victim, 1000)`, burning 1000 ERC20 tokens and receiving 1000 `evm/0xMAL` native tokens.
3. Attacker calls `drain(victim, 1000)` from `MaliciousContract`. The bank precompile executes `bankKeeper.SendCoins(victim, attacker, 1000 evm/0xMAL)` with no authorization check.
4. Victim's 1000 `evm/0xMAL` native tokens are transferred to the attacker. The victim's ERC20 tokens were already burned in step 2 and cannot be recovered.

**Relevant code locations:** [1](#0-0) 

The missing check — `sender` is taken from call arguments without verifying it equals `contract.Caller()`: [2](#0-1) 

The denom is scoped to the calling contract, but the `from` address is not: [3](#0-2) 

Contrast with the authenticated pattern used in the relayer/ICA precompiles: [4](#0-3)

### Citations

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
