### Title
Unauthorized Token Transfer via Missing Caller Authorization in `BankContract.transfer` — (File: x/cronos/keeper/precompiles/bank.go)

---

### Summary

The `transfer` method in the `BankContract` precompile allows any EVM contract to move `evm/<caller_address>` native tokens **from an arbitrary `sender` address** without verifying that the caller is authorized to spend from that address. This is a direct auth bypass: a malicious contract can drain `evm/` denom tokens from any holder without the holder's consent.

---

### Finding Description

In `BankContract.Run`, the `transfer` case constructs the denom from `contract.Caller()` but accepts `sender` as a free argument from the call input:

```go
// x/cronos/keeper/precompiles/bank.go, TransferMethodName case
sender := args[0].(common.Address)
recipient := args[1].(common.Address)
amount := args[2].(*big.Int)
...
from := sdk.AccAddress(sender.Bytes())
to   := sdk.AccAddress(recipient.Bytes())
...
denom := EVMDenom(contract.Caller())          // evm/0x<calling_contract>
amt   := sdk.NewCoin(denom, ...)
...
bc.bankKeeper.SendCoins(ctx, from, to, sdk.NewCoins(amt))
``` [1](#0-0) 

There is **no check** that `contract.Caller() == sender`, and no allowance/approval mechanism. The bank module's `SendCoins` will succeed as long as `from` holds enough `evm/<caller>` balance — regardless of whether `from` ever authorized the calling contract to move those funds.

The `burn` case has the same pattern (burns from an arbitrary `recipient` address without authorization): [2](#0-1) 

---

### Impact Explanation

**Critical — Unauthorized transfer of `evm/` prefixed native tokens.**

`evm/<contract_address>` tokens are Cosmos SDK native coins managed by the EVM contract. They back CRC20-style assets. Any contract can:

1. Mint `evm/<itself>` tokens to users (legitimate airdrop, reward, LP receipt, etc.).
2. Later call `bank.transfer(victim, attacker, amount)` to move those tokens out of the victim's account with no approval from the victim.

The victim's balance is reduced and the attacker's balance is increased — a direct, unauthorized asset transfer.

---

### Likelihood Explanation

**Medium.** The attacker must first get victims to hold `evm/<attacker_contract>` tokens (via `mint`, a prior `transfer`, or an IBC receive that auto-converts). Once any user holds such tokens, the contract can drain them at will. A malicious token contract deployed on Cronos can exploit this immediately after users interact with it.

---

### Recommendation

In the `TransferMethodName` case, enforce that the caller is authorized to move funds from `sender`. The simplest fix is to require `contract.Caller() == sender`:

```go
if contract.Caller() != sender {
    return nil, errors.New("caller is not authorized to transfer from sender")
}
```

Alternatively, implement an ERC20-style allowance mapping stored in the bank precompile so that `sender` can explicitly approve the calling contract to spend on their behalf.

The same fix should be applied to the `BurnMethodName` case, which also burns from an arbitrary address without authorization.

---

### Proof of Concept

**Attack path (unprivileged):**

1. Attacker deploys `MaliciousToken` contract at address `0xMalicious`.
2. `MaliciousToken` calls `bank.mint(victim_address, 1_000_000)` → victim now holds `1_000_000 evm/0xMalicious` tokens.
3. Victim sees a balance and may interact with the token (e.g., provide liquidity, use as collateral).
4. Attacker calls `bank.transfer(victim_address, attacker_address, 1_000_000)` from `MaliciousToken`.
5. `BankContract.Run` computes `denom = "evm/0xMalicious"`, calls `bankKeeper.SendCoins(victim, attacker, evm/0xMalicious, 1_000_000)`.
6. No authorization check is performed. The transfer succeeds. Victim's balance is zero; attacker holds all tokens.

The missing guard is at `x/cronos/keeper/precompiles/bank.go` lines 175–196: there is no `contract.Caller() == sender` assertion before `SendCoins` is invoked. [3](#0-2)

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
