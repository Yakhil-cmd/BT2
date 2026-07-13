The question's framing about blocked module accounts is a red herring — `checkBlockedAddr` works correctly. But there is a real, distinct vulnerability in the `transfer` path: the `sender` argument is taken from ABI calldata and never verified against `contract.Caller()`.

---

### Title
Unauthenticated `sender` in bank precompile `transfer` allows calling contract to drain any holder of its denom — (`File: x/cronos/keeper/precompiles/bank.go`)

### Summary

The `TransferMethodName` branch of `BankContract.Run` reads `sender` from ABI-decoded calldata and passes it directly to `bankKeeper.SendCoins` as the `from` address, with no check that it equals `contract.Caller()`. Any EVM contract can therefore move `evm/<itself>` tokens out of any account that holds them, without that account's consent.

### Finding Description

In the `transfer` case:

```
sender := args[0].(common.Address)   // line 175 — fully attacker-controlled
...
from := sdk.AccAddress(sender.Bytes()) // line 181
...
denom := EVMDenom(contract.Caller())   // line 186 — evm/<actual_caller>
...
bc.bankKeeper.SendCoins(ctx, from, to, sdk.NewCoins(amt)) // line 192
``` [1](#0-0) 

`contract.Caller()` fixes the denom to `evm/<caller_contract>`, but `from` is taken from calldata. There is no guard of the form `if sender != contract.Caller() { return error }`. The Cosmos SDK's `SendCoins` performs no authorization check of its own — it is the caller's responsibility. [2](#0-1) 

The same pattern exists in `burn`: `addr` (args[0]) is the account whose tokens are burned, and it is never compared to `contract.Caller()`. [3](#0-2) 

By contrast, every other precompile in the codebase that performs a privileged action derives the acting principal from `contract.Caller()` and validates it against the message signer before executing: [4](#0-3) 

### Impact Explanation

A malicious (or compromised) EVM contract at address `0xATTACKER`:

1. Mints `evm/0xATTACKER` tokens to victim accounts (or victims receive them via a DEX/bridge).
2. Calls the bank precompile `transfer(victim, attacker, balance)` — `sender` = victim, `recipient` = attacker.
3. `SendCoins` moves the victim's entire `evm/0xATTACKER` balance to the attacker with no revert.

This is an **unauthorized transfer** of precompile-controlled assets, matching the Critical impact category. The constraint is that only tokens of the calling contract's own denom (`evm/<caller>`) can be stolen, but that is precisely the denom users hold when they interact with that contract.

### Likelihood Explanation

Any unprivileged user can deploy an EVM contract and call the bank precompile. No admin key, governance vote, or leaked secret is required. The exploit is a single EVM call.

### Recommendation

Add a caller-equality guard before `SendCoins`:

```go
if sender != contract.Caller() {
    return nil, errors.New("sender must be the caller")
}
```

Apply the same fix to the `burn` case (verify `recipient == contract.Caller()`), or explicitly document that the calling contract has sovereign control over all balances of its denom and ensure users are warned accordingly.

### Proof of Concept

```
// Attacker contract (Solidity pseudocode)
interface IBank {
    function mint(address recipient, uint256 amount) external returns (bool);
    function transfer(address sender, address recipient, uint256 amount) external returns (bool);
}

address constant BANK = address(100); // bankContractAddress

function stealFrom(address victim, uint256 amount) external {
    // denom = evm/<address(this)>
    // No check that msg.sender == victim inside the precompile
    IBank(BANK).transfer(victim, address(this), amount);
}
```

The call succeeds as long as `victim` holds a nonzero balance of `evm/<attacker_contract>` and `amount > 0`. [5](#0-4) 

---

**On the question's specific invariant** ("blocked module accounts cannot receive user-controlled precompile funds"): `checkBlockedAddr` is called correctly on the `to` address for both `mint` and `transfer`, so that invariant holds. The vulnerability is orthogonal — it is the missing authorization check on the `from`/`sender` side. [6](#0-5)

### Citations

**File:** x/cronos/keeper/precompiles/bank.go (L92-101)
```go
func (bc *BankContract) checkBlockedAddr(addr sdk.AccAddress) error {
	to, err := sdk.AccAddressFromBech32(addr.String())
	if err != nil {
		return err
	}
	if bc.bankKeeper.BlockedAddr(to) {
		return errorsmod.Wrapf(errortypes.ErrUnauthorized, "%s is not allowed to receive funds", to.String())
	}
	return nil
}
```

**File:** x/cronos/keeper/precompiles/bank.go (L144-144)
```go
				if err := bc.bankKeeper.SendCoinsFromAccountToModule(ctx, addr, types.ModuleName, sdk.NewCoins(amt)); err != nil {
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

**File:** x/cronos/types/interfaces.go (L29-29)
```go
	SendCoins(ctx context.Context, senderAddr, recipientAddr sdk.AccAddress, amt sdk.Coins) error
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
