### Title
Unchecked `sender` Address in Bank Precompile `transfer` and `burn` Allows Any Contract to Drain or Destroy Arbitrary Holders' `evm/<contract>` Tokens — (File: `x/cronos/keeper/precompiles/bank.go`)

### Summary
The bank precompile's `transfer` and `burn` methods accept a caller-supplied address as the token source without verifying that the calling contract is authorized to act on behalf of that address. Any deployed contract can call these methods to move or destroy `evm/<callerContract>` native bank tokens from any holder's account without the holder's consent.

### Finding Description
In `x/cronos/keeper/precompiles/bank.go`, the `Run` function handles three state-mutating methods. For `transfer` (lines 167–200), the `sender` field is taken directly from ABI-decoded calldata (`args[0]`) and used as the `from` address in `bankKeeper.SendCoins`:

```go
sender := args[0].(common.Address)
recipient := args[1].(common.Address)
...
from := sdk.AccAddress(sender.Bytes())
to := sdk.AccAddress(recipient.Bytes())
denom := EVMDenom(contract.Caller())          // evm/<callingContract>
...
bc.bankKeeper.SendCoins(ctx, from, to, sdk.NewCoins(amt))
```

There is no check that `sender == contract.Caller()` or that `sender` has granted an allowance to the calling contract. The denom is `evm/<contract.Caller()>`, so the calling contract controls which token is moved, but it can move that token from **any** address.

The same pattern applies to `burn` (lines 113–156). The parameter named `recipient` is actually the address to burn **from**:

```go
recipient := args[0].(common.Address)   // misleadingly named; this is the burn-from address
...
addr := sdk.AccAddress(recipient.Bytes())
denom := EVMDenom(contract.Caller())
...
bc.bankKeeper.SendCoinsFromAccountToModule(ctx, addr, types.ModuleName, sdk.NewCoins(amt))
bc.bankKeeper.BurnCoins(ctx, types.ModuleName, sdk.NewCoins(amt))
```

Again, no check that `addr == contract.Caller()` or that `addr` has authorized the burn.

### Impact Explanation
**Critical — Unauthorized transfer and burn of `evm/<contract>` native bank tokens.**

`evm/<contract>` tokens are real Cosmos SDK bank-module assets. They are issued when a CRC20/CRC21 contract uses the bank precompile to mint native representations of its token (e.g., for IBC bridging or native-side accounting). Once users hold `evm/ContractA` tokens in their bank accounts, the operator of ContractA can:

1. Call `transfer(victimAddress, attackerAddress, amount)` → moves victim's tokens to attacker with no consent.
2. Call `burn(victimAddress, amount)` → destroys victim's tokens with no consent.

This is a complete rug-pull primitive: a contract issuer can drain or destroy every holder's balance at will, constituting an unauthorized balance/accounting change for precompile-controlled assets.

### Likelihood Explanation
Any unprivileged actor can deploy a contract and call the bank precompile directly. No admin key, governance vote, or validator compromise is required. The entry path is a standard EVM transaction calling the bank precompile at address `0x0000…0064`. The only precondition is that victims hold `evm/<attackerContract>` tokens, which the attacker can engineer by first minting tokens to users (e.g., via a DeFi protocol facade) and then draining them.

### Recommendation
In the `transfer` case, verify that the `sender` argument equals `contract.Caller()`, or implement an allowance/approval mechanism before permitting third-party transfers:

```go
if sender != contract.Caller() {
    return nil, errors.New("transfer: sender must be the calling contract")
}
```

In the `burn` case, verify that the burn target is `contract.Caller()` itself, or require an explicit approval from the target address before burning:

```go
if recipient != contract.Caller() {
    return nil, errors.New("burn: can only burn from the calling contract's own account")
}
```

### Proof of Concept

1. Attacker deploys `MaliciousToken` contract at address `0xDEAD`.
2. `MaliciousToken` calls bank precompile `mint(aliceAddress, 1_000_000)` → Alice now holds `1,000,000 evm/0xDEAD` tokens.
3. `MaliciousToken` calls bank precompile `transfer(aliceAddress, attackerEOA, 1_000_000)`:
   - `sender = aliceAddress` (ABI arg, no authorization check)
   - `denom = evm/0xDEAD`
   - `bankKeeper.SendCoins(aliceAddr, attackerAddr, coins)` executes unconditionally
4. Alice's entire `evm/0xDEAD` balance is transferred to the attacker with no signature or approval from Alice.
5. Alternatively, step 3 can be replaced with `burn(aliceAddress, 1_000_000)` to destroy Alice's tokens entirely.

The attack requires only two standard EVM transactions and zero privileged access. [1](#0-0) [2](#0-1) [3](#0-2)

### Citations

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
