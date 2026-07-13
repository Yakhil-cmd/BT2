### Title
Bank Precompile `transfer` Accepts Arbitrary `sender` Without Caller Authorization — (`File: x/cronos/keeper/precompiles/bank.go`)

### Summary
The bank precompile's `transfer` method takes the `sender` address directly from calldata and executes `bankKeeper.SendCoins(ctx, from, to, ...)` without verifying that `contract.Caller()` equals `sender`. Any unprivileged EVM contract can therefore drain `evm/<callerContract>`-denominated native tokens from any victim account that holds them.

### Finding Description

In `x/cronos/keeper/precompiles/bank.go`, the `Run` function handles the `transfer` selector as follows:

```go
case TransferMethodName:
    args, err := method.Inputs.Unpack(contract.Input[4:])
    sender    := args[0].(common.Address)   // ← taken from calldata, not from contract.Caller()
    recipient := args[1].(common.Address)
    amount    := args[2].(*big.Int)
    ...
    from := sdk.AccAddress(sender.Bytes())
    to   := sdk.AccAddress(recipient.Bytes())
    ...
    denom := EVMDenom(contract.Caller())    // denom = "evm/<callerContractAddress>"
    ...
    bc.bankKeeper.SendCoins(ctx, from, to, sdk.NewCoins(amt))
``` [1](#0-0) 

There is no guard of the form `if sender != contract.Caller() { return error }`. The `denom` is correctly scoped to `evm/<callerContractAddress>`, but the **source of funds** (`from`) is fully attacker-controlled.

Compare this with the `relayer` and `ica` precompiles, which use the `exec` helper in `utils.go` that explicitly enforces `caller == signer`:

```go
caller := common.BytesToAddress(signers[0])
if caller != e.caller {
    return nil, fmt.Errorf("caller is not authenticated: expected %s, got %s", ...)
}
``` [2](#0-1) 

The bank precompile's `transfer` case does **not** use this pattern and has no equivalent check.

The same missing check exists for the `burn` case: `recipient` (the address to burn from) is taken from calldata without verifying it equals `contract.Caller()`. [3](#0-2) 

### Impact Explanation

**Critical — Unauthorized transfer/burn of precompile-controlled native assets.**

An attacker deploys `AttackerContract` at address `0xATK`. Any user who holds `evm/0xATK`-denominated native tokens (e.g., because they previously called `moveToNative` on `AttackerContract`, or received such tokens via IBC conversion) can have those tokens stolen. `AttackerContract` calls:

```solidity
IBankModule(0x64).transfer(victimAddress, attackerAddress, victimBalance);
```

The bank module executes `SendCoins(ctx, victim, attacker, amount)` with no authorization from `victim`. This is an unauthorized balance change for precompile-controlled assets, matching the Critical impact tier.

### Likelihood Explanation

Medium. The attacker must control the contract whose address forms the denom (`evm/<callerContract>`), and victims must hold that specific denom. This is a realistic scenario: any CRC20-style contract that exposes `moveToNative` (as shown in `TestBank.sol`) creates victims holding `evm/<contract>` native tokens. The attacker simply deploys such a contract, waits for users to convert, then drains them. [4](#0-3) 

### Recommendation

Add a caller-authorization check in the `transfer` case (and symmetrically in the `burn` case) before executing the bank operation:

```go
case TransferMethodName:
    ...
    sender := args[0].(common.Address)
    // Enforce that only the token holder (or the contract itself) can initiate a transfer
    if sender != contract.Caller() {
        return nil, errors.New("sender does not match caller")
    }
    ...
```

Alternatively, remove the `sender` argument entirely and derive it from `contract.Caller()`, consistent with how `mint` derives the denom from `contract.Caller()`.

### Proof of Concept

1. Attacker deploys `AttackerContract` at `0xATK`.
2. Alice calls `AttackerContract.moveToNative(100)` → Alice now holds 100 `evm/0xATK` native tokens in the Cosmos bank module.
3. Attacker calls from `AttackerContract`:
   ```solidity
   IBankModule(0x0000000000000000000000000000000000000064)
       .transfer(alice, attacker, 100);
   ```
4. `BankContract.Run` unpacks `sender = alice`, `recipient = attacker`, `denom = "evm/0xATK"`.
5. No caller check is performed. `bankKeeper.SendCoins(ctx, alice, attacker, 100 evm/0xATK)` executes.
6. Alice's 100 `evm/0xATK` tokens are transferred to the attacker without Alice's consent. [5](#0-4) [6](#0-5)

### Citations

**File:** x/cronos/keeper/precompiles/bank.go (L103-111)
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

**File:** x/cronos/keeper/precompiles/utils.go (L46-49)
```go
	caller := common.BytesToAddress(signers[0])
	if caller != e.caller {
		return nil, fmt.Errorf("caller is not authenticated: expected %s, got %s", e.caller.Hex(), caller.Hex())
	}
```
