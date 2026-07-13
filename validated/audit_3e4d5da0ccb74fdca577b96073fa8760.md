### Title
Bank Precompile `transfer` and `burn` Allow Unauthorized Draining of Any User's `evm/` Denom Balance — (`File: x/cronos/keeper/precompiles/bank.go`)

### Summary
The bank precompile's `transfer` and `burn` methods accept an arbitrary `sender`/`recipient` address argument but derive the token denom solely from `contract.Caller()`. There is no check that the caller is authorized to spend from the supplied address. Any deployed EVM contract can therefore drain or destroy `evm/<contract_address>` tokens held by any user without that user's consent.

### Finding Description

In `bank.go`, the `TransferMethodName` case unpacks a `sender` argument from calldata and passes it directly as the `from` address to `bankKeeper.SendCoins`:

```go
sender := args[0].(common.Address)
recipient := args[1].(common.Address)
amount := args[2].(*big.Int)
...
from := sdk.AccAddress(sender.Bytes())
to   := sdk.AccAddress(recipient.Bytes())
denom := EVMDenom(contract.Caller())          // evm/<calling_contract>
amt   := sdk.NewCoin(denom, ...)
...
bc.bankKeeper.SendCoins(ctx, from, to, sdk.NewCoins(amt))
``` [1](#0-0) 

There is no assertion that `sender == contract.Caller()` or that `sender` has approved the calling contract to spend on its behalf. The denom is `evm/<contract.Caller()>`, so the calling contract is the sole issuer of that denom — but it can freely move balances it does not own.

The same pattern applies to `BurnMethodName`: the `recipient` argument (the address whose tokens are burned) is taken directly from calldata with no authorization check:

```go
recipient := args[0].(common.Address)
...
addr := sdk.AccAddress(recipient.Bytes())
denom := EVMDenom(contract.Caller())
...
bc.bankKeeper.SendCoinsFromAccountToModule(ctx, addr, types.ModuleName, sdk.NewCoins(amt))
bc.bankKeeper.BurnCoins(ctx, types.ModuleName, sdk.NewCoins(amt))
``` [2](#0-1) 

### Impact Explanation

**Critical — Unauthorized transfer/burn of precompile-controlled assets.**

Any EVM contract (deployed by an unprivileged user) that has previously minted `evm/<contract_address>` tokens to users can, at any later time, call `transfer(victim, attacker, balance)` or `burn(victim, balance)` to silently drain or destroy the victim's entire balance of that denom. No approval, signature, or permission from the victim is required. This satisfies the Critical impact class: *"Unauthorized transfer … for … precompile-controlled assets."*

### Likelihood Explanation

**Medium.** The attacker only needs to:
1. Deploy an EVM contract (permissionless).
2. Have users acquire `evm/<contract_address>` tokens (e.g., via the same contract's `mint` call, a DeFi integration, or an airdrop).
3. Call the bank precompile's `transfer` or `burn` from within the contract.

No privileged keys, governance votes, or validator compromise are required.

### Recommendation

In the `TransferMethodName` case, enforce that the `sender` argument equals `contract.Caller()` (mirroring ERC-20 `transfer` semantics), or implement an allowance/approval mechanism before permitting third-party transfers. For `BurnMethodName`, similarly restrict burning to tokens held by `contract.Caller()` itself, or require an explicit approval from the token holder.

```go
// transfer: only allow moving tokens owned by the calling contract itself
if sender != contract.Caller() {
    return nil, errors.New("unauthorized: sender must be the calling contract")
}
```

### Proof of Concept

1. Attacker deploys `MaliciousToken` at address `0xDEAD`. The contract calls `bankPrecompile.mint(alice, 1000)` — Alice now holds `1000 evm/0xDEAD`.
2. Later, `MaliciousToken` calls `bankPrecompile.transfer(alice, attacker_eoa, 1000)`.
3. `BankContract.Run` sets `from = alice`, `denom = evm/0xDEAD`, and executes `bankKeeper.SendCoins(ctx, alice, attacker_eoa, [{evm/0xDEAD, 1000}])`.
4. Alice's entire `evm/0xDEAD` balance is transferred to the attacker with no signature or approval from Alice. [3](#0-2)

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
