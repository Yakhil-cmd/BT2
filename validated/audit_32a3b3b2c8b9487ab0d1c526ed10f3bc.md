### Title
Bank Precompile `transfer` Allows Unauthorized Token Transfer from Arbitrary Sender Addresses — (File: x/cronos/keeper/precompiles/bank.go)

---

### Summary

The `transfer` method of the `BankContract` precompile accepts an arbitrary `sender` address as a caller-supplied argument and uses it directly as the `from` address in `bankKeeper.SendCoins`, without verifying that the calling contract is authorized to move tokens on behalf of that address. Any unprivileged EVM contract can invoke `transfer(victimAddress, attackerAddress, amount)` to drain `evm/<callerContract>` native tokens from any holder without the holder's consent.

---

### Finding Description

In `x/cronos/keeper/precompiles/bank.go`, the `Run` method handles the `transfer` case as follows:

```go
sender := args[0].(common.Address)   // caller-supplied, arbitrary
recipient := args[1].(common.Address)
...
from := sdk.AccAddress(sender.Bytes())
to   := sdk.AccAddress(recipient.Bytes())
denom := EVMDenom(contract.Caller())  // evm/<callingContract>
amt   := sdk.NewCoin(denom, ...)
...
bc.bankKeeper.SendCoins(ctx, from, to, sdk.NewCoins(amt))
``` [1](#0-0) 

The denom is correctly scoped to the calling contract (`EVMDenom(contract.Caller())`), but `from` is taken verbatim from the ABI-decoded argument — there is **no check that `sender == contract.Caller()`** and no allowance/approval mechanism. The `mint` and `burn` cases use `contract.Caller()` to derive the recipient/target address, but `transfer` uniquely accepts an arbitrary `sender`, creating an asymmetry. [2](#0-1) 

The analog to the external report is exact: just as `addEarnings` modifies earnings state without calling `isValidForEarnings`, the `transfer` case modifies token balances without calling any check that the `sender` argument is the contract itself (or has approved the move).

---

### Impact Explanation

Any EVM contract that has ever minted `evm/<contract>` tokens to users (e.g., as a payment, reward, or DeFi position token) can later call `transfer(victimAddress, attackerAddress, amount)` on the bank precompile to reclaim or redirect those tokens from any holder without their consent. This constitutes an **unauthorized transfer of precompile-controlled native assets**, matching the Critical impact tier:

> *Unauthorized transfer … for … precompile-controlled assets* [3](#0-2) 

---

### Likelihood Explanation

The entry path is fully unprivileged: any deployed EVM contract can call the bank precompile at address `0x0000…0064`. No admin key, governance vote, or special permission is required. The attacker only needs to have previously minted `evm/<contract>` tokens to a victim (or to have a victim acquire them through any means), then call `transfer` with the victim as `sender`. [4](#0-3) 

---

### Recommendation

Add an authorization check in the `transfer` case that enforces `sender == contract.Caller()`:

```go
if sender != contract.Caller() {
    return nil, errors.New("transfer: sender must be the calling contract")
}
```

Alternatively, implement an ERC20-style allowance mapping so that a contract can only transfer tokens from addresses that have explicitly approved it. The `mint` and `burn` cases already correctly use `contract.Caller()` as the authority; `transfer` should follow the same pattern. [5](#0-4) 

---

### Proof of Concept

1. Attacker deploys `MaliciousContract` at address `0xATK`.
2. `MaliciousContract` calls `bank.mint(victimAddress, 1000)` → victim now holds `1000 evm/0xATK` native tokens.
3. At any later time, `MaliciousContract` calls `bank.transfer(victimAddress, attackerAddress, 1000)`.
4. Inside `BankContract.Run`, `from = victimAddress`, `denom = evm/0xATK`, and `bankKeeper.SendCoins(ctx, victimAddress, attackerAddress, 1000 evm/0xATK)` executes with no authorization check.
5. Victim's `evm/0xATK` balance is drained to the attacker without any approval or signature from the victim.

The missing guard — analogous to the absent `isValidForEarnings` call — is the absent `sender == contract.Caller()` check before `SendCoins` is invoked. [6](#0-5)

### Citations

**File:** x/cronos/keeper/precompiles/bank.go (L30-33)
```go
var (
	bankABI                 abi.ABI
	bankContractAddress     = common.BytesToAddress([]byte{100})
	bankGasRequiredByMethod = map[[4]byte]uint64{}
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
