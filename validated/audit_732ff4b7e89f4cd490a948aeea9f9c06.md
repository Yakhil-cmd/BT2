### Title
Unauthorized Transfer of Native Bank Tokens via Missing Caller Authorization in Bank Precompile `transfer` — (File: `x/cronos/keeper/precompiles/bank.go`)

### Summary
The bank precompile's `transfer` method accepts an arbitrary `sender` address as a calldata argument and transfers native bank tokens from that address without verifying that the calling contract is authorized to spend on the sender's behalf. Any contract can drain native bank tokens (denom `"evm/<callerContractAddress>"`) from any holder of that denom.

### Finding Description

In `x/cronos/keeper/precompiles/bank.go`, the `Run()` function handles the `transfer` method as follows:

```go
case TransferMethodName:
    ...
    sender := args[0].(common.Address)   // taken from calldata, not from contract.Caller()
    recipient := args[1].(common.Address)
    amount := args[2].(*big.Int)
    ...
    from := sdk.AccAddress(sender.Bytes())
    to := sdk.AccAddress(recipient.Bytes())
    ...
    denom := EVMDenom(contract.Caller())  // "evm/0x<callerContract>"
    ...
    if err := bc.bankKeeper.SendCoins(ctx, from, to, sdk.NewCoins(amt)); err != nil {
``` [1](#0-0) 

The `sender` is taken directly from the ABI-decoded arguments (line 175), not from `contract.Caller()`. There is **no check** that `contract.Caller() == sender` and no allowance/approval mechanism. The denom is `"evm/" + contract.Caller().Hex()`, so the calling contract controls which denom is transferred, and it can specify any `sender` address as the source.

Compare this to the `mint`/`burn` branch, which also uses `contract.Caller()` to derive the denom but at least operates on a specified `recipient` — the `transfer` branch uniquely allows the caller to drain from an arbitrary third-party address. [2](#0-1) 

The bank precompile is designed to be called by CRC20/CRC21 contracts to manage their native bank token counterparts. The `TestBank.sol` integration test shows the intended usage pattern: a contract calls `bank.mint(msg.sender, amount)` after burning its own ERC20 tokens, giving the user native bank tokens with denom `"evm/0x<contract>"`. [3](#0-2) 

Once a user holds `"evm/0x<ContractA>"` native bank tokens, **any call from `ContractA`** (including a malicious path within that contract) can invoke `bank.transfer(victimAddress, attackerAddress, amount)` and drain those tokens without the victim's consent.

### Impact Explanation

**Critical — Unauthorized transfer of precompile-controlled assets.**

A contract that has issued native bank tokens to users (via `bank.mint`) can at any time call `bank.transfer(victim, attacker, balance)` to steal all of those native bank tokens from every holder. Because the denom is `"evm/0x<contract>"`, only that contract can perform this transfer — but the contract itself has unrestricted ability to move any holder's balance to any address. There is no approval, allowance, or consent mechanism protecting holders.

### Likelihood Explanation

Any user who calls a CRC20 contract's `moveToNative()`-style function (burning ERC20 tokens and receiving native bank tokens via `bank.mint`) is exposed. The attacker only needs to control the CRC20 contract (e.g., deploy a malicious one, or exploit an upgradeable one). No privileged Cosmos keys are required — only the ability to deploy and call an EVM contract.

### Recommendation

In the `TransferMethodName` branch of `BankContract.Run()`, enforce that the `sender` argument equals `contract.Caller()`:

```go
if sender != contract.Caller() {
    return nil, errors.New("sender must be the calling contract")
}
```

This restricts each contract to transferring only tokens it holds itself (i.e., its own module account balance), matching the security model used by `mint_by_cronos_module` / `burn_by_cronos_module` in the Solidity contracts, which gate privileged operations to `msg.sender == module_address`. [4](#0-3) 

### Proof of Concept

1. Deploy `MaliciousToken` at address `0xMalicious` with a `deposit()` function:
   ```solidity
   function deposit(uint256 amount) external {
       // burn user's ERC20 tokens
       _burn(msg.sender, amount);
       // mint native bank tokens to user: denom = "evm/0xMalicious"
       bank.mint(msg.sender, amount);
   }
   function steal(address victim, address attacker, uint256 amount) external {
       // no authorization check in bank precompile — succeeds
       bank.transfer(victim, attacker, amount);
   }
   ```
2. Victim calls `deposit(100)` — they now hold 100 `"evm/0xMalicious"` native bank tokens.
3. Attacker calls `steal(victim, attacker, 100)` — the bank precompile executes `SendCoins(victim → attacker, 100 "evm/0xMalicious")` with no authorization check.
4. Victim's native bank tokens are drained. The attacker can then call `moveFromNative()` (or `bank.burn` + `_mint`) to convert them back to ERC20 tokens. [5](#0-4)

### Citations

**File:** x/cronos/keeper/precompiles/bank.go (L113-131)
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

**File:** contracts/src/ModuleCRC20.sol (L31-39)
```text
    function mint_by_cronos_module(address addr, uint amount) public {
        require(msg.sender == module_address);
        mint(addr, amount);
    }

    function burn_by_cronos_module(address addr, uint amount) public {
        require(msg.sender == module_address);
        unsafe_burn(addr, amount);
    }
```
