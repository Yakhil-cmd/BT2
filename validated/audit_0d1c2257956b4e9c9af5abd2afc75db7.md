### Title
Unauthorized Native Token Drain via Missing Caller Validation in Bank Precompile `transfer` — (`x/cronos/keeper/precompiles/bank.go`)

---

### Summary

The bank precompile's `transfer` handler accepts `sender` as a caller-supplied ABI argument and uses it directly as the `from` address for `bankKeeper.SendCoins`, without ever verifying that `sender == contract.Caller()`. Any EVM contract can therefore invoke `transfer(victim, attacker, amount)` and drain the victim's `evm/<calling_contract_address>` native Cosmos tokens without the victim's consent.

---

### Finding Description

In `BankContract.Run`, the `TransferMethodName` case unpacks three ABI arguments: `sender`, `recipient`, and `amount`. The `sender` value is taken verbatim from the call data and converted to a Cosmos `AccAddress` (`from`). The denom is derived from `contract.Caller()` — the address of the EVM contract that called the precompile — producing `evm/<caller_hex>`. The precompile then executes `bankKeeper.SendCoins(ctx, from, to, ...)` with no check that `from` equals `contract.Caller()`.

```
// bank.go lines 175-192 (simplified)
sender    := args[0].(common.Address)   // ← fully attacker-controlled
recipient := args[1].(common.Address)
from      := sdk.AccAddress(sender.Bytes())
denom     := EVMDenom(contract.Caller()) // evm/<calling contract>
bankKeeper.SendCoins(ctx, from, to, ...)  // no from == Caller() check
```

The analogous flaw in the external report is `reassignOwner` (which internally calls `validateOwner()` to assert `msg.sender == owner`) being placed in `acceptOwnership` instead of `transferOwnership`, so the wrong caller is validated. Here the equivalent guard — asserting `sender == contract.Caller()` — is simply absent from the `transfer` path entirely.

The `mint` and `burn` paths share the same structure (recipient taken from ABI args, no caller check), but `transfer` is the highest-impact case because it moves existing tokens between arbitrary accounts rather than creating or destroying supply.

---

### Impact Explanation

**Critical — Unauthorized transfer of CRC20/native precompile-controlled assets.**

Any EVM contract can call `transfer(victim, attacker, N)` on the bank precompile. The precompile will move `N` units of `evm/<calling_contract_address>` from the victim's Cosmos-side balance to the attacker's address. Users who hold native `evm/<contract>` tokens (obtained by converting CRC20 tokens for IBC transfer or other Cosmos-side use) can have those balances stolen with no approval or signature from them.

---

### Likelihood Explanation

The attacker must control a contract whose `evm/<address>` denom is held by victims. This is achievable by deploying a CRC20 token, attracting users who convert their ERC20 balance to the native denom (e.g., to bridge via IBC), and then calling the precompile's `transfer` function directly from that contract. The bank precompile is a fixed address (`0x0000…0064`) reachable by any EVM contract with no access restriction.

---

### Recommendation

Add a caller-equality guard immediately after unpacking arguments in the `TransferMethodName` case:

```go
if sender != contract.Caller() {
    return nil, errors.New("transfer: sender must equal caller")
}
```

This mirrors the pattern already used in `precompiles/utils.go` (`exec`), where `caller != e.caller` is checked before any state mutation.

---

### Proof of Concept

```solidity
// Attacker contract deployed at 0xATTACKER
interface IBankPrecompile {
    function transfer(address sender, address recipient, uint256 amount)
        external returns (bool);
}

contract Drain {
    IBankPrecompile constant bank =
        IBankPrecompile(0x0000000000000000000000000000000000000064);

    // attacker calls this; victim must hold evm/0xATTACKER native tokens
    function steal(address victim, address attacker, uint256 amount) external {
        bank.transfer(victim, attacker, amount);
    }
}
```

1. Attacker deploys `Drain` at `0xATTACKER`.
2. Victim converts some `evm/0xATTACKER` CRC20 tokens to native Cosmos balance (e.g., to IBC-transfer them).
3. Attacker calls `Drain.steal(victim, attacker, victimBalance)`.
4. `bankKeeper.SendCoins` moves `evm/0xATTACKER` tokens from `victim` to `attacker` — no victim signature required.

---

**Relevant code locations:** [1](#0-0) [2](#0-1) [3](#0-2)

### Citations

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

**File:** x/cronos/keeper/precompiles/utils.go (L46-49)
```go
	caller := common.BytesToAddress(signers[0])
	if caller != e.caller {
		return nil, fmt.Errorf("caller is not authenticated: expected %s, got %s", e.caller.Hex(), caller.Hex())
	}
```
