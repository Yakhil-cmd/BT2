### Title
Unchecked `sender` in Bank Precompile `transfer` Enables Unauthorized Theft of Precompile-Controlled Assets — (File: `x/cronos/keeper/precompiles/bank.go`)

---

### Summary

The bank precompile's `transfer` method accepts the `sender` address as a caller-supplied ABI argument and immediately calls `bankKeeper.SendCoins(ctx, from, to, ...)` without verifying that the EVM contract invoking the precompile has any authorization from that `sender`. Because the denom is derived from the calling contract's own address (`evm/<contract.Caller()>`), any contract that has previously minted `evm/<itself>` tokens to users can unilaterally drain those balances to an arbitrary recipient — with no consent from the token holder.

---

### Finding Description

In `bank.go`, the `TransferMethodName` case of `BankContract.Run` is:

```go
sender    := args[0].(common.Address)   // attacker-controlled
recipient := args[1].(common.Address)   // attacker-controlled
amount    := args[2].(*big.Int)

from := sdk.AccAddress(sender.Bytes())
to   := sdk.AccAddress(recipient.Bytes())
// ...
denom := EVMDenom(contract.Caller())    // "evm/<calling_contract>"
amt   := sdk.NewCoin(denom, sdkmath.NewIntFromBigInt(amount))
err = stateDB.ExecuteNativeAction(precompileAddr, nil, func(ctx sdk.Context) error {
    // ...
    if err := bc.bankKeeper.SendCoins(ctx, from, to, sdk.NewCoins(amt)); err != nil {
``` [1](#0-0) 

`sender` is taken verbatim from the ABI-decoded input. There is no check that `contract.Caller()` equals `sender`, no ERC-20-style allowance, and no `msg.sender == from` guard. The only constraint is that the denom is namespaced to the calling contract, so the contract can only move tokens of its own denom — but it can move them from **any** holder of that denom.

Compare with the `mint` path, which correctly derives the recipient from ABI arguments but uses `contract.Caller()` as the denom authority: [2](#0-1) 

The `mint` path establishes that a contract is the sole issuer of `evm/<itself>` tokens. The `transfer` path then lets that same contract move those tokens out of any holder's account without consent — a capability that is never restricted.

---

### Impact Explanation

**Critical — Unauthorized transfer of precompile-controlled assets.**

`evm/<contract_address>` tokens are native Cosmos SDK coins managed exclusively through the bank precompile. Any EVM contract that has distributed these tokens (e.g., as liquidity shares, receipt tokens, or collateral in a DeFi protocol) can later call `transfer(victim, attacker, balance)` to drain every holder's balance in a single transaction. The victim's native-coin balance decreases and the attacker's increases; no approval or signature from the victim is required. This satisfies the Critical criterion: *unauthorized transfer of precompile-controlled assets*.

---

### Likelihood Explanation

The attack requires only that:
1. A contract (malicious or later-compromised) has previously minted `evm/<itself>` tokens to users via the `mint` method.
2. The contract calls `transfer(victim, attacker, amount)` — a single EVM call, no privileged key needed.

Any unprivileged contract deployer can execute this. The bank precompile is a production surface reachable by any EVM transaction.

---

### Recommendation

Enforce that the EVM caller is the token sender. In the `TransferMethodName` case, add:

```go
if contract.Caller() != sender {
    return nil, errors.New("bank precompile transfer: caller is not the sender")
}
```

Alternatively, implement an allowance model (analogous to ERC-20 `approve`/`transferFrom`) so that a contract may only move tokens from a third-party address if that address has explicitly granted an allowance. This mirrors the "allowlist of trusted origins" fix recommended in the external report — restricting which callers may act on behalf of a given address.

---

### Proof of Concept

```
1. Attacker deploys contract M.
2. M calls bank.mint(victim, 1_000_000) 
   → victim now holds 1_000_000 evm/M tokens (native coins).
3. M calls bank.transfer(victim, attacker, 1_000_000)
   → bankKeeper.SendCoins(victim → attacker, 1_000_000 evm/M) executes.
   → No signature or approval from victim is checked.
4. Victim's evm/M balance: 0. Attacker's evm/M balance: 1_000_000.
```

The only precondition is that `victim` holds `evm/M` tokens — a condition the attacker can arrange by first calling `mint`. In a realistic scenario, a DeFi protocol issues `evm/<protocol_contract>` tokens as LP shares; the protocol contract (or an attacker who compromises it) can then sweep all LP shares from all holders in one block.

### Citations

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

**File:** x/cronos/keeper/precompiles/bank.go (L167-196)
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
```
