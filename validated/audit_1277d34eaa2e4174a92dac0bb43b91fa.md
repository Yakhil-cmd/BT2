### Title
`ModuleCRC20Proxy.transfer_from_cronos_module` Releases Tokens from Wrong Address, Permanently Locking CRC20 Tokens - (File: `contracts/src/ModuleCRC20Proxy.sol`)

### Summary

`ModuleCRC20Proxy.sol`'s `transfer_by_cronos_module` escrows CRC20 tokens at `module_address`, but `transfer_from_cronos_module` attempts to release them from `address(this)` (the proxy contract). These are two distinct addresses. Any user who converts source-denom CRC21 tokens to native via `ConvertCoinFromCRC21ToNative` will have their CRC20 tokens permanently locked at `module_address`, and the reverse conversion via `ConvertCoinFromNativeToCRC21` will fail because the proxy holds no balance.

### Finding Description

In `contracts/src/ModuleCRC20Proxy.sol`, the two module-facing transfer functions use inconsistent escrow addresses:

**`transfer_by_cronos_module`** — escrows at `module_address`:
```solidity
function transfer_by_cronos_module(address addr, uint amount) public {
    require(msg.sender == module_address);
    crc20Contract.move(addr, module_address, amount);  // tokens → module_address
}
``` [1](#0-0) 

**`transfer_from_cronos_module`** — releases from `address(this)` (the proxy), not `module_address`:
```solidity
function transfer_from_cronos_module(address addr, uint amount) public {
    require(msg.sender == module_address);
    crc20Contract.move(address(this), addr, amount);  // releases from proxy, NOT module_address
}
``` [2](#0-1) 

Compare with the correct implementation in `ModuleCRC21.sol`, where both functions consistently use `module_address`:
```solidity
function transfer_by_cronos_module(address addr, uint amount) public {
    unsafe_transfer(addr, module_address, amount);  // escrow → module_address
}
function transfer_from_cronos_module(address addr, uint amount) public {
    transferFrom(module_address, addr, amount);     // release ← module_address ✓
}
``` [3](#0-2) 

The keeper calls these functions in the CRC21↔native conversion path. `ConvertCoinFromCRC21ToNative` calls `transfer_by_cronos_module` (tokens go to `module_address`), and `ConvertCoinFromNativeToCRC21` calls `transfer_from_cronos_module` (tries to release from `address(this)` — the proxy — which holds nothing): [4](#0-3) [5](#0-4) 

### Impact Explanation

When a user calls `ConvertCoinFromCRC21ToNative` on a source token (`cronos0x...` denom) backed by a `ModuleCRC20Proxy`:
1. Their CRC20 tokens are moved to `module_address` via `transfer_by_cronos_module`.
2. Native tokens are minted and sent to the user.

When the user later calls `ConvertCoinFromNativeToCRC21` to reverse this:
1. Their native tokens are burned.
2. `transfer_from_cronos_module` attempts `crc20Contract.move(address(this), sender, amount)` — but the proxy holds zero balance.
3. The call reverts with insufficient balance.

Result: native tokens are burned but CRC20 tokens cannot be released. The CRC20 tokens are permanently locked at `module_address` with no recovery path. This is a **Critical accounting corruption**: unauthorized permanent loss of CRC20 token balance for users, and a permanent inability to process the native→CRC21 conversion flow for any `ModuleCRC20Proxy`-backed source token.

### Likelihood Explanation

An admin must register a `ModuleCRC20Proxy` as an external contract for a `cronos0x...` source denom via `RegisterOrUpdateTokenMapping`. This is a legitimate use case (external CRC20 contracts wrapped by a proxy). Once registered, any unprivileged user calling `ConvertCoinFromCRC21ToNative` followed by `ConvertCoinFromNativeToCRC21` triggers the permanent loss. The admin setup is a prerequisite, not a mitigation.

### Recommendation

Fix `transfer_from_cronos_module` in `ModuleCRC20Proxy.sol` to release from `module_address` instead of `address(this)`, matching the escrow destination used by `transfer_by_cronos_module`:

```solidity
// Before (wrong):
function transfer_from_cronos_module(address addr, uint amount) public {
    require(msg.sender == module_address);
    crc20Contract.move(address(this), addr, amount);
}

// After (correct):
function transfer_from_cronos_module(address addr, uint amount) public {
    require(msg.sender == module_address);
    crc20Contract.move(module_address, addr, amount);
}
```

### Proof of Concept

1. Admin registers a `ModuleCRC20Proxy`-backed external contract for a source denom `cronos0x<addr>` via `MsgUpdateTokenMapping`.
2. User holds 100 CRC20 tokens at their EVM address.
3. User calls `ConvertCoinFromCRC21ToNative` (or the precompile equivalent):
   - Keeper calls `transfer_by_cronos_module(userAddr, 100)` → `crc20Contract.move(userAddr, module_address, 100)` — 100 tokens now at `module_address`.
   - Keeper mints 100 native `cronos0x<addr>` tokens to user.
4. User calls `ConvertCoinFromNativeToCRC21`:
   - Keeper burns 100 native tokens from user.
   - Keeper calls `transfer_from_cronos_module(userAddr, 100)` → `crc20Contract.move(address(this), userAddr, 100)` — proxy has 0 balance → **REVERT**.
5. Native tokens are burned, CRC20 tokens remain permanently locked at `module_address`. User has lost 100 tokens with no recovery path. [6](#0-5) [7](#0-6) [8](#0-7)

### Citations

**File:** contracts/src/ModuleCRC20Proxy.sol (L51-59)
```text
    function transfer_by_cronos_module(address addr, uint amount) public {
        require(msg.sender == module_address);
        crc20Contract.move(addr, module_address, amount);
    }

    function transfer_from_cronos_module(address addr, uint amount) public {
        require(msg.sender == module_address);
        crc20Contract.move(address(this), addr, amount);
    }
```

**File:** contracts/src/ModuleCRC21.sol (L46-53)
```text
    function transfer_by_cronos_module(address addr, uint amount) public {
        require(msg.sender == module_address);
        unsafe_transfer(addr, module_address, amount);
    }

    function transfer_from_cronos_module(address addr, uint amount) public {
        transferFrom(module_address, addr, amount);
    }
```

**File:** x/cronos/keeper/evm.go (L90-144)
```go
// ConvertCoinFromNativeToCRC21 convert native token to erc20 token
func (k Keeper) ConvertCoinFromNativeToCRC21(ctx sdk.Context, sender common.Address, coin sdk.Coin, autoDeploy bool) error {
	if !types.IsValidCoinDenom(coin.Denom) {
		return fmt.Errorf("coin %s is not supported for conversion", coin.Denom)
	}
	var err error
	// external contract is returned in preference to auto-deployed ones
	contract, found := k.GetContractByDenom(ctx, coin.Denom)
	if !found {
		if !autoDeploy {
			return fmt.Errorf("no contract found for the denom %s", coin.Denom)
		}
		contract, err = k.DeployModuleCRC21(ctx, coin.Denom)
		if err != nil {
			return err
		}
		if err = k.SetAutoContractForDenom(ctx, coin.Denom, contract); err != nil {
			return err
		}

		k.Logger(ctx).Info(fmt.Sprintf("contract address %s created for coin denom %s", contract.String(), coin.Denom))
	}

	isSource := types.IsSourceCoin(coin.Denom)
	coins := sdk.NewCoins(coin)
	if isSource {
		// burn coins
		err = k.bankKeeper.SendCoinsFromAccountToModule(ctx, sdk.AccAddress(sender.Bytes()), types.ModuleName, sdk.NewCoins(coin))
		if err != nil {
			return err
		}
		err = k.bankKeeper.BurnCoins(ctx, types.ModuleName, coins)
		if err != nil {
			return err
		}
		// unlock crc tokens
		_, err = k.CallModuleCRC21(ctx, contract, "transfer_from_cronos_module", sender, coin.Amount.BigInt())
		if err != nil {
			return err
		}
	} else {
		// send coins to contract address
		err = k.bankKeeper.SendCoins(ctx, sdk.AccAddress(sender.Bytes()), sdk.AccAddress(contract.Bytes()), coins)
		if err != nil {
			return err
		}
		// mint crc tokens
		_, err = k.CallModuleCRC21(ctx, contract, "mint_by_cronos_module", sender, coin.Amount.BigInt())
		if err != nil {
			return err
		}
	}

	return nil
}
```

**File:** x/cronos/keeper/evm.go (L146-185)
```go
// ConvertCoinFromCRC21ToNative convert erc20 token to native token
func (k Keeper) ConvertCoinFromCRC21ToNative(ctx sdk.Context, contract, receiver common.Address, amount sdkmath.Int) error {
	denom, found := k.GetDenomByContract(ctx, contract)
	if !found {
		return fmt.Errorf("the contract address %s is not mapped to native token", contract.String())
	}

	isSource := types.IsSourceCoin(denom)
	coins := sdk.NewCoins(sdk.NewCoin(denom, amount))

	if isSource {
		_, err := k.CallModuleCRC21(ctx, contract, "transfer_by_cronos_module", receiver, amount.BigInt())
		if err != nil {
			return err
		}
		if err = k.bankKeeper.MintCoins(ctx, types.ModuleName, coins); err != nil {
			return err
		}
		if err = k.bankKeeper.SendCoinsFromModuleToAccount(ctx, types.ModuleName, sdk.AccAddress(receiver.Bytes()), coins); err != nil {
			return err
		}
	} else {
		err := k.bankKeeper.SendCoins(
			ctx,
			sdk.AccAddress(contract.Bytes()),
			sdk.AccAddress(receiver.Bytes()),
			coins,
		)
		if err != nil {
			return err
		}

		_, err = k.CallModuleCRC21(ctx, contract, "burn_by_cronos_module", receiver, amount.BigInt())
		if err != nil {
			return err
		}
	}

	return nil
}
```
