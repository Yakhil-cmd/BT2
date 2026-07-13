### Title
Bank Precompile `transfer` and `burn` Use Caller-Supplied Address as Fund Source Without Authorization Check — (`File: x/cronos/keeper/precompiles/bank.go`)

### Summary
The bank precompile's `transfer` and `burn` methods accept the source address as an ABI-encoded argument from the caller rather than deriving it from `contract.Caller()`. Any EVM contract can therefore drain or destroy `evm/<contract>` tokens held by any victim address without holding any authorization from that victim.

### Finding Description
In `x/cronos/keeper/precompiles/bank.go`, the `Run` function dispatches on method name. For `TransferMethodName`:

```go
sender := args[0].(common.Address)   // line 175 – arbitrary, from call data
recipient := args[1].(common.Address)
amount := args[2].(*big.Int)
...
from := sdk.AccAddress(sender.Bytes())
to   := sdk.AccAddress(recipient.Bytes())
denom := EVMDenom(contract.Caller())  // line 186 – denom tied to calling contract
...
bc.bankKeeper.SendCoins(ctx, from, to, sdk.NewCoins(amt))  // line 192
```

`sender` (the debit source) is taken verbatim from the ABI input; `contract.Caller()` is used only to derive the denom, never to authorize the debit. There is no check that `sender == contract.Caller()` or that `contract.Caller()` holds an allowance from `sender`.

The same pattern applies to `BurnMethodName`:

```go
recipient := args[0].(common.Address)   // line 121 – the address to burn FROM
...
bc.bankKeeper.SendCoinsFromAccountToModule(ctx, addr, types.ModuleName, ...)  // line 144
bc.bankKeeper.BurnCoins(ctx, types.ModuleName, ...)                           // line 147
```

`addr` is the address whose balance is debited; it is caller-supplied with no authorization check. [1](#0-0) [2](#0-1) 

### Impact Explanation
The denom is `EVMDenom(contract.Caller())` = `"evm/0x<calling_contract>"`. Tokens with this denom are real Cosmos SDK bank balances. Any EVM contract can:

1. **Steal** — call `transfer(victim, attacker, amount)` to move `evm/<calling_contract>` tokens from `victim` to `attacker` with no approval.
2. **Destroy** — call `burn(victim, amount)` to permanently destroy `evm/<calling_contract>` tokens held by `victim` with no approval.

For the attack to reach real value, the victim must hold `evm/<calling_contract>` tokens. This is reachable because:
- The same contract can first call `mint(victim, amount)` to seed the victim with tokens (e.g., as part of a liquidity/staking flow), then call `transfer(victim, attacker, amount)` to reclaim them.
- Any legitimate contract that issues `evm/<contract>` tokens to users (e.g., a CRC20 wrapper using the bank precompile) exposes all its token holders to theft by any party who can trigger a call into that contract with crafted arguments, because the precompile itself never enforces `sender == contract.Caller()`.

This is an **unauthorized transfer and burn of precompile-controlled assets**, matching the Critical impact tier. [3](#0-2) 

### Likelihood Explanation
The bank precompile is a live, registered precompile at address `0x0000...0064`. Any unprivileged EVM transaction can call it directly or through a contract. No special role, key, or governance action is required. The only precondition is that the victim holds a balance of the denom `evm/<calling_contract>`, which is achievable by the attacker themselves via `mint`. [4](#0-3) 

### Recommendation
Replace the caller-supplied `sender` with `contract.Caller()` in the `transfer` case, and replace the caller-supplied `recipient` (burn target) with `contract.Caller()` in the `burn` case. The calling contract is the only entity whose authorization the precompile can verify; it should only be permitted to debit its own address:

```go
// transfer: debit only the calling contract's own bank address
from := sdk.AccAddress(contract.Caller().Bytes())

// burn: burn only from the calling contract's own bank address
addr := sdk.AccAddress(contract.Caller().Bytes())
```

If third-party transfers are intentionally required, an explicit on-chain allowance registry (analogous to ERC-20 `approve`/`transferFrom`) must be added and checked before `SendCoins` is called.

### Proof of Concept

1. Attacker deploys contract `A` at address `0xA`.
2. `A` calls bank precompile `mint(victim, 1000)` → victim now holds 1000 `evm/0xA` tokens.
3. `A` calls bank precompile `transfer(victim, attacker_eoa, 1000)` → `bankKeeper.SendCoins(victim, attacker_eoa, 1000 evm/0xA)` executes with no authorization check.
4. Victim's balance is zero; attacker holds 1000 `evm/0xA` tokens.

Alternatively, for the burn path:
- Step 3: `A` calls `burn(victim, 1000)` → `bankKeeper.SendCoinsFromAccountToModule(victim, ...)` + `BurnCoins(...)` executes, permanently destroying the victim's tokens.

Both paths require only an unprivileged EVM transaction and are reachable on mainnet. [5](#0-4) [6](#0-5)

### Citations

**File:** x/cronos/keeper/precompiles/bank.go (L30-33)
```go
var (
	bankABI                 abi.ABI
	bankContractAddress     = common.BytesToAddress([]byte{100})
	bankGasRequiredByMethod = map[[4]byte]uint64{}
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

**File:** x/cronos/keeper/precompiles/bank.go (L112-155)
```go
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
