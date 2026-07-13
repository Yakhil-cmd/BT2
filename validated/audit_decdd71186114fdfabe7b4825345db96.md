Now I have enough context to analyze the finding. Let me read the ModuleCRC21 source and check how the bank precompile is registered/called.

### Title
Bank Precompile `transfer` Moves Funds From Arbitrary `sender` Parameter Instead of `contract.Caller()` - (File: x/cronos/keeper/precompiles/bank.go)

### Summary
The `transfer` method of the bank precompile accepts a `sender` address as a calldata parameter and moves native bank tokens **from that arbitrary address** without verifying it equals `contract.Caller()`. Any EVM contract can therefore drain another account's native `evm/`-denom balance by supplying a victim address as `sender`.

### Finding Description
The bank precompile at `bankContractAddress` (address `0x64`) exposes four methods: `mint`, `burn`, `balanceOf`, and `transfer`. In the `transfer` case the implementation is:

```go
// x/cronos/keeper/precompiles/bank.go  L167-L200
case TransferMethodName:
    args, err := method.Inputs.Unpack(contract.Input[4:])
    sender    := args[0].(common.Address)   // ← arbitrary caller-supplied address
    recipient := args[1].(common.Address)
    amount    := args[2].(*big.Int)
    from := sdk.AccAddress(sender.Bytes())
    to   := sdk.AccAddress(recipient.Bytes())
    denom := EVMDenom(contract.Caller())    // "evm/" + callerContractHex
    amt   := sdk.NewCoin(denom, ...)
    // ...
    bc.bankKeeper.SendCoins(ctx, from, to, sdk.NewCoins(amt))  // from = victim
```

`sender` (line 175) comes directly from calldata. There is no guard of the form `sender == contract.Caller()`. The denom is derived from `contract.Caller()` (line 186), so the denomination is `evm/<callerContractAddress>`. Any EVM contract that calls the precompile can supply an arbitrary victim address as `sender` and the bank module will execute `SendCoins` from that victim's account.

The same structural flaw exists in the `burn` branch: `recipient` (args[0], line 121) is the address whose balance is debited via `SendCoinsFromAccountToModule`, again without verifying it equals `contract.Caller()`. [1](#0-0) [2](#0-1) 

### Impact Explanation
**Critical – Unauthorized transfer of precompile-controlled assets.**

A malicious EVM contract that has previously issued `evm/<contractAddress>` native bank tokens to users (e.g., via the `mint` method of the same precompile, or via the `ConvertVouchers` / IBC-receive flow that mints native coins to a CRC21 contract address) can call `transfer(victim, attacker, balance)` and move the victim's entire native bank balance of that denom to the attacker with no approval from the victim. The `bankKeeper.SendCoins` call is unconditional once the denom and amount are valid. [3](#0-2) 

### Likelihood Explanation
The bank precompile is reachable by any deployed EVM contract with no privilege requirement. The constraint is that the victim must hold native bank tokens whose denom is `evm/<attackerContractAddress>`. This is a realistic condition whenever:
- A CRC21 source-token contract has been used and users hold the corresponding native denom after conversion.
- A DeFi contract mints receipt tokens via the `mint` method and users hold those receipts as native bank coins.

An attacker who controls such a contract (or deploys a new one and lures users into holding its denom) can immediately drain all holders. [4](#0-3) [5](#0-4) 

### Recommendation
Enforce that the `sender` in `transfer` and the `recipient` in `burn` must equal `contract.Caller()`:

```go
// transfer
if sender != contract.Caller() {
    return nil, errors.New("sender must be the calling contract")
}

// burn
if recipient != contract.Caller() {
    return nil, errors.New("burn target must be the calling contract")
}
```

This mirrors the fix applied to the PolicyBook analog: only the contract that owns the denom (i.e., `contract.Caller()`) should be permitted to initiate transfers or burns from a specific account. If third-party delegation is intentionally needed, an explicit on-chain allowance mechanism must be added. [6](#0-5) 

### Proof of Concept
1. Deploy `AttackerContract` at address `0xATK` on Cronos EVM.
2. Call `AttackerContract.setup(victim)`:
   - Internally calls bank precompile `mint(victim, 1000)` → mints `1000 evm/0xATK` native coins to `victim`. (Alternatively, victim already holds `evm/0xATK` from a prior legitimate interaction.)
3. Call `AttackerContract.drain(victim, attacker)`:
   - Internally calls bank precompile `transfer(victim, attacker, 1000)`.
   - The precompile executes `bankKeeper.SendCoins(victim, attacker, [{denom:"evm/0xATK", amount:1000}])` with no consent from `victim`.
4. `victim`'s `evm/0xATK` balance is now 0; `attacker`'s balance is 1000.

No signature, allowance, or governance action from the victim is required at any step. [7](#0-6) [1](#0-0)

### Citations

**File:** x/cronos/keeper/precompiles/bank.go (L56-58)
```go
func EVMDenom(token common.Address) string {
	return EVMDenomPrefix + token.Hex()
}
```

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
