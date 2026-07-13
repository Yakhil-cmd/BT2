### Title
Unauthorized Burn and Transfer of Native `evm/` Tokens via Bank Precompile — (`x/cronos/keeper/precompiles/bank.go`)

---

### Summary
The bank precompile's `burn` and `transfer` methods accept the victim address as a caller-supplied argument with no authorization check. Any unprivileged smart contract can burn or steal native `evm/<callerContract>` tokens from any user who holds them, without the user's consent.

---

### Finding Description

The `BankContract.Run` function in `x/cronos/keeper/precompiles/bank.go` exposes three state-mutating methods: `mint`, `burn`, and `transfer`. The denom for all three is derived from the calling contract's address:

```go
denom := EVMDenom(contract.Caller())   // "evm/0x<callerContract>"
```

For `burn`, the address to burn **from** is taken directly from `args[0]` (user-supplied), with no check that the caller is authorized to act on behalf of that address:

```go
recipient := args[0].(common.Address)   // attacker-controlled
addr := sdk.AccAddress(recipient.Bytes())
// only checkBlockedAddr — no ownership/authorization check
bc.bankKeeper.SendCoinsFromAccountToModule(ctx, addr, types.ModuleName, sdk.NewCoins(amt))
bc.bankKeeper.BurnCoins(ctx, types.ModuleName, sdk.NewCoins(amt))
```

For `transfer`, the `sender` (i.e., the `from` address for `SendCoins`) is likewise taken from `args[0]` with no check that it equals `contract.Caller()`:

```go
sender := args[0].(common.Address)   // attacker-controlled
from := sdk.AccAddress(sender.Bytes())
// no check: sender == contract.Caller()
bc.bankKeeper.SendCoins(ctx, from, to, sdk.NewCoins(amt))
```

The only guard present is `checkBlockedAddr`, which only rejects Cosmos module accounts — it does not verify that the caller is authorized to spend from the supplied address. [1](#0-0) [2](#0-1) 

---

### Impact Explanation

**Critical — Unauthorized burn and transfer of precompile-controlled native assets.**

Any smart contract can:
1. Call `bank.burn(victimAddress, amount)` to destroy a victim's `evm/<callerContract>` native tokens without their consent.
2. Call `bank.transfer(victimAddress, attackerAddress, amount)` to move a victim's `evm/<callerContract>` native tokens to an arbitrary recipient.

These `evm/<address>` tokens are real native Cosmos-layer assets. The `TestBank.sol` integration contract demonstrates the intended usage pattern — users burn their ERC20 balance and receive native `evm/<contract>` tokens via `bank.mint`:

```solidity
function moveToNative(uint256 amount) public returns (bool) {
    _burn(msg.sender, amount);
    return bank.mint(msg.sender, amount);
}
``` [3](#0-2) 

Once a user holds `evm/<attackerContract>` native tokens, the attacker's contract can drain or destroy them at will.

---

### Likelihood Explanation

**Low-Medium.** The attacker must be the deployer of a contract that users interact with and hold native `evm/<contract>` tokens from. This requires social engineering or a legitimate-looking contract that uses the bank precompile's `mint` flow. No admin, governance, or key compromise is required — any contract deployer can exploit this.

---

### Recommendation

In the `burn` case, validate that the address being burned from is the calling contract itself (i.e., `args[0] == contract.Caller()`), or require explicit on-chain approval. In the `transfer` case, validate that `sender == contract.Caller()` before calling `SendCoins`. The denom is already scoped to the caller's address; the spend authorization must be scoped the same way.

```go
// burn: enforce caller == subject
if recipient != contract.Caller() {
    return nil, errors.New("burn: caller must be the token holder")
}

// transfer: enforce sender == caller
if sender != contract.Caller() {
    return nil, errors.New("transfer: sender must be the calling contract")
}
``` [4](#0-3) [5](#0-4) 

---

### Proof of Concept

1. Attacker deploys `MaliciousToken` at address `0xDEAD`, which exposes a `moveToNative` pattern so users accumulate `evm/0xDEAD` native tokens.
2. Victim calls `MaliciousToken.moveToNative(100)` → their ERC20 balance is burned, and they receive 100 `evm/0xDEAD` native tokens via `bank.mint(victimAddress, 100)`.
3. Attacker calls a drain function on `MaliciousToken`:
   ```solidity
   function drain(address victim, uint256 amount) external {
       bank.transfer(victim, msg.sender, amount);
       // or: bank.burn(victim, amount);
   }
   ```
4. The bank precompile executes `SendCoins(victimCosmosAddr, attackerCosmosAddr, 100 evm/0xDEAD)` with no authorization check — victim's native tokens are stolen (or destroyed).

The root cause is the missing `sender == contract.Caller()` guard in `BankContract.Run` at `x/cronos/keeper/precompiles/bank.go` lines 175–192 (transfer) and the missing `recipient == contract.Caller()` guard at lines 120–150 (burn). [6](#0-5) [7](#0-6)

### Citations

**File:** x/cronos/keeper/precompiles/bank.go (L56-58)
```go
func EVMDenom(token common.Address) string {
	return EVMDenomPrefix + token.Hex()
}
```

**File:** x/cronos/keeper/precompiles/bank.go (L103-204)
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
	default:
		return nil, errors.New("unknown method")
	}
}
```

**File:** integration_tests/contracts/contracts/TestBank.sol (L14-17)
```text
    function moveToNative(uint256 amount) public returns (bool) {
        _burn(msg.sender, amount);
        return bank.mint(msg.sender, amount);
    }
```
