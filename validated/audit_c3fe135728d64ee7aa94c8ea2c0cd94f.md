### Title
Unauthorized Transfer and Burn of Bank Precompile Assets via Missing Caller Authorization Check — (File: x/cronos/keeper/precompiles/bank.go)

---

### Summary

The bank precompile's `transfer` and `burn` methods accept a caller-supplied `sender` address without verifying that the calling contract is authorized to act on behalf of that address. Any EVM contract can transfer or burn `evm/<contract_address>`-denominated Cosmos bank tokens from any holder without their consent.

---

### Finding Description

In `x/cronos/keeper/precompiles/bank.go`, the `TransferMethodName` case unpacks `sender` directly from ABI-encoded caller input and passes it as the `from` address to `bankKeeper.SendCoins` with no check that `contract.Caller() == sender`: [1](#0-0) 

```go
sender := args[0].(common.Address)   // ← fully attacker-controlled
recipient := args[1].(common.Address)
...
from := sdk.AccAddress(sender.Bytes())
to   := sdk.AccAddress(recipient.Bytes())
...
denom := EVMDenom(contract.Caller())  // denom tied to calling contract
...
bc.bankKeeper.SendCoins(ctx, from, to, sdk.NewCoins(amt))
```

The denom is `evm/<contract.Caller()>`, so the tokens being moved are those issued by the calling contract. There is no allowance/approval mechanism and no assertion that `from == contract.Caller()` or that `from` has approved the caller to spend on its behalf.

The same pattern exists in the `BurnMethodName` branch, where `args[0]` (named `recipient` in the variable but used as the address to debit) is passed directly to `bankKeeper.SendCoinsFromAccountToModule` without authorization: [2](#0-1) 

---

### Impact Explanation

**Critical — Unauthorized transfer/burn of bank-precompile-managed assets.**

Any EVM contract that has previously issued `evm/<contract_address>` tokens to users can, at any time and without user consent:

- Call `transfer(victim, attacker, amount)` to drain the victim's balance to an arbitrary address.
- Call `burn(victim, amount)` to destroy the victim's balance.

Because these tokens live in the Cosmos `x/bank` module (not EVM storage), standard ERC20 `approve`/`transferFrom` guards do not apply. The bank module's `SendCoins` enforces no caller-level authorization beyond module-account rules; the precompile is the sole gatekeeper and it performs no check.

---

### Likelihood Explanation

**Medium.** The victim must hold tokens of the denom `evm/<attacker_contract_address>`. This is realistic because:

1. A legitimate protocol mints `evm/X` tokens to users as rewards, liquidity receipts, or wrapped assets.
2. A compromised or malicious contract at address X can then drain all holders at once.
3. The `mint` method itself is unrestricted (any contract can mint its own denom to any address), so an attacker can seed victims with tokens and immediately steal them back — or wait until victims accumulate a balance organically.

---

### Recommendation

In the `TransferMethodName` branch, assert that the caller is the sender before executing the transfer:

```go
if contract.Caller() != sender {
    return nil, errors.New("transfer: caller is not the sender")
}
```

Alternatively, implement an ERC20-style allowance mapping inside the precompile so that a contract may only transfer tokens on behalf of an address that has explicitly approved it.

Apply the same fix to the `BurnMethodName` branch: verify `contract.Caller() == recipient` (the address being debited) before burning.

---

### Proof of Concept

1. Attacker deploys malicious contract `M` on Cronos EVM.
2. `M` calls bank precompile (`0x0000…0064`) method `mint(victim, 1_000e18)` — mints 1 000 `evm/M` tokens to `victim`. (No restriction prevents this.)
3. Victim now holds 1 000 `evm/M` tokens in the Cosmos bank module.
4. `M` calls bank precompile method `transfer(victim, attacker, 1_000e18)`.
5. The precompile unpacks `sender = victim`, constructs `denom = "evm/" + M.address`, and calls `bankKeeper.SendCoins(ctx, victim, attacker, 1000evm/M)` — **no authorization check is performed**.
6. Victim's balance is drained to attacker with zero consent from victim.

The same four-step flow applies to `burn`: replace step 4 with `burn(victim, 1_000e18)` to destroy the victim's balance instead of redirecting it. [3](#0-2)

### Citations

**File:** x/cronos/keeper/precompiles/bank.go (L121-149)
```go
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
