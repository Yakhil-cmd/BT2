### Title
Bank Precompile `transfer` Allows Any Contract to Move Tokens from Arbitrary Holders Without Authorization - (File: x/cronos/keeper/precompiles/bank.go)

### Summary
The `transfer` method of the bank precompile does not validate that the `sender` argument matches `contract.Caller()`. Any EVM contract can invoke `transfer(victimAddress, attackerAddress, amount)` on the bank precompile and move native Cosmos tokens (denom `evm/<callerAddress>`) out of any holder's account without that holder's consent.

### Finding Description
The bank precompile at `x/cronos/keeper/precompiles/bank.go` exposes four methods: `mint`, `burn`, `balanceOf`, and `transfer`. The denom for all operations is derived from the calling contract's address:

```go
denom := EVMDenom(contract.Caller())   // "evm/0x<callerContract>"
```

For the `transfer` case the precompile unpacks a caller-supplied `sender` address and immediately uses it as the debit account:

```go
sender := args[0].(common.Address)
recipient := args[1].(common.Address)
// ...
from := sdk.AccAddress(sender.Bytes())
to   := sdk.AccAddress(recipient.Bytes())
// ...
bc.bankKeeper.SendCoins(ctx, from, to, sdk.NewCoins(amt))
``` [1](#0-0) 

There is no guard of the form `require sender == contract.Caller()`. The only validation present is a blocked-address check on the *recipient*, not the sender. [2](#0-1) 

The same structural omission exists in the `burn` branch: the address to burn from is taken verbatim from the first argument with no check that it equals the calling contract. [3](#0-2) 

The integration test contract `TestBank.sol` shows the intended usage pattern — the contract passes `msg.sender` as the sender — but the precompile itself never enforces this invariant. [4](#0-3) 

### Impact Explanation
Any EVM contract can call `bankPrecompile.transfer(victimAddress, attackerAddress, amount)`. Because the denom is scoped to the calling contract (`evm/0x<callerContract>`), the attacker must first have victims hold tokens of that denom (e.g., by operating a token contract that mints to users). Once victims hold the tokens, the contract can drain every holder's balance to an arbitrary address in a single call, with no on-chain approval or allowance mechanism to block it. This constitutes an **unauthorized transfer of precompile-controlled assets** — Critical under the allowed impact scope.

### Likelihood Explanation
The entry path is fully unprivileged: any deployed EVM contract can call the bank precompile. A realistic attack is a token contract that mints `evm/0xAttacker` tokens to users (e.g., as a yield token or wrapped asset) and later calls `transfer` to sweep all balances. No leaked keys, governance access, or cryptographic break is required.

### Recommendation
Add a caller-equality guard before executing the transfer:

```go
if sender != contract.Caller() {
    return nil, errors.New("transfer: sender must equal contract caller")
}
```

Apply the same guard to `burn` (the first argument must equal `contract.Caller()`). Alternatively, redesign the `transfer` interface to omit the `sender` argument entirely and always debit `contract.Caller()`, matching the implicit trust model already used for `mint` and `burn`. [5](#0-4) 

### Proof of Concept

1. Attacker deploys `MaliciousToken` at address `0xMalicious`. The contract calls `bankPrecompile.mint(alice, 1_000_000)` — Alice now holds `1_000_000 evm/0xMalicious` native tokens.
2. Attacker calls `MaliciousToken.steal(alice, attacker, 1_000_000)`, which internally calls:
   ```solidity
   IBankModule(0x64).transfer(alice, attacker, 1_000_000);
   ```
3. The bank precompile executes `bankKeeper.SendCoins(ctx, alice, attacker, [{denom:"evm/0xMalicious", amount:1_000_000}])` with no authorization check.
4. Alice's entire balance is transferred to the attacker. Alice receives nothing in return. [6](#0-5)

### Citations

**File:** x/cronos/keeper/precompiles/bank.go (L121-144)
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

**File:** integration_tests/contracts/contracts/TestBank.sol (L35-38)
```text
    function nativeTransfer(address recipient, uint256 amount) public returns (bool) {
        _transfer(msg.sender, recipient, amount);
        return bank.transfer(msg.sender, recipient, amount);
    }
```
