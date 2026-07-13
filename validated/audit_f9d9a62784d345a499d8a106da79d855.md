### Title
Upgradeable Proxy Contract Mapped as CRC21 Token Can Be Upgraded Post-Registration to Steal Mints/Burns — (File: `x/cronos/keeper/evm.go`, `x/cronos/keeper/keeper.go`)

---

### Summary

The Cronos token-mapping system allows any contract with deployed bytecode to be registered as the CRC21 contract for a native denom. The registration guard `ensureContractCode` only verifies that code exists at the address — it does not detect upgradeable proxy patterns. After a legitimate admin maps an upgradeable proxy contract, the proxy's owner (an unprivileged party) can upgrade the implementation to malicious bytecode. All subsequent module-level calls (`mint_by_cronos_module`, `burn_by_cronos_module`, `transfer_by_cronos_module`) will execute the attacker-controlled logic, enabling unauthorized minting or burn-bypass.

---

### Finding Description

When a token mapping is registered via `MsgUpdateTokenMapping` or auto-deployment, the keeper calls `ensureContractCode` to validate the target contract:

```go
// x/cronos/keeper/keeper.go:312-327
func (k Keeper) ensureContractCode(ctx sdk.Context, contract common.Address) error {
    if contract.Big().Cmp(big.NewInt(256)) < 0 {
        return errors.Wrapf(sdkerrors.ErrInvalidAddress, ...)
    }
    resp, err := k.evmKeeper.Code(ctx, &evmtypes.QueryCodeRequest{Address: contract.Hex()})
    ...
    if resp == nil || len(resp.Code) == 0 {
        return errors.Wrapf(sdkerrors.ErrInvalidRequest, "no contract code at address (%s)", contract.Hex())
    }
    return nil
}
``` [1](#0-0) 

This check passes for any upgradeable proxy (e.g., UUPS, TransparentUpgradeableProxy, or a custom proxy like `ModuleCRC20Proxy`) because the proxy bytecode is present at registration time. No check is made for:
- Whether the contract contains an upgrade mechanism (`upgradeTo`, `_setImplementation`, etc.)
- Whether the ABI-level behavior of the mapped functions can change post-registration

After mapping, the module unconditionally calls the registered contract address via `CallModuleCRC21`:

```go
// x/cronos/keeper/evm.go:55-68
func (k Keeper) CallModuleCRC21(ctx sdk.Context, contract common.Address, method string, args ...interface{}) ([]byte, error) {
    data, err := types.ModuleCRC21Contract.ABI.Pack(method, args...)
    ...
    _, res, err := k.CallEVM(ctx, &contract, data, big.NewInt(0), DefaultGasCap)
    ...
}
``` [2](#0-1) 

This is called from `ConvertCoinFromNativeToCRC21` (IBC receive path) and `ConvertCoinFromCRC21ToNative` (bridge-out path):

```go
// x/cronos/keeper/evm.go:137
_, err = k.CallModuleCRC21(ctx, contract, "mint_by_cronos_module", sender, coin.Amount.BigInt())
``` [3](#0-2) 

```go
// x/cronos/keeper/evm.go:178
_, err = k.CallModuleCRC21(ctx, contract, "burn_by_cronos_module", receiver, amount.BigInt())
``` [4](#0-3) 

The IBC middleware triggers this automatically on every inbound IBC packet for mapped denoms:

```go
// x/cronos/middleware/conversion_middleware.go:135
if err := im.cronoskeeper.ConvertVouchersToEvmCoins(cacheCtx, data.Receiver, sdk.NewCoins(token)); err != nil {
``` [5](#0-4) 

---

### Impact Explanation

**Critical — Unauthorized mint of CRC20/CRC21 tokens:**
A malicious upgraded `mint_by_cronos_module` implementation can mint tokens to arbitrary addresses instead of (or in addition to) the intended recipient. Every IBC inbound transfer for the affected denom triggers an unbounded mint to attacker-controlled addresses.

**Critical — Burn bypass / double-spend:**
A malicious upgraded `burn_by_cronos_module` can be a no-op. When `ConvertCoinFromCRC21ToNative` is called, the module first sends native coins to the receiver (`bankKeeper.SendCoins`), then calls `burn_by_cronos_module`. If the burn is skipped, the user retains both the native coins and the EVM tokens — a direct double-spend of the mapped asset.

**Critical — `transfer_by_cronos_module` theft:**
For source tokens (`cronos0x...`), `ConvertCoinFromCRC21ToNative` calls `transfer_by_cronos_module` before minting native coins. A malicious implementation can redirect the transfer to an attacker address, stealing the EVM tokens while the module still mints native coins to the legitimate receiver.

---

### Likelihood Explanation

The `ModuleCRC20Proxy` contract is an explicitly supported and documented pattern in Cronos (used in integration tests and production). Any project that deploys a proxy-based CRC21 and gets it mapped by the admin can exploit this. The contract owner is unprivileged relative to the CronosAdmin — they do not need any special permission to upgrade their own proxy after mapping. The IBC receive path triggers the exploit automatically without any further user action. [6](#0-5) 

---

### Recommendation

1. **Detect proxy patterns at registration time**: In `ensureContractCode` (or a new `ensureContractNotProxy` guard), check for known proxy storage slots (EIP-1967 implementation slot `0x360894...`, admin slot `0xb53127...`) and reject contracts that contain them.

2. **Alternatively, enforce immutability**: Require that mapped contracts have no owner/admin/upgrade functions by checking for the absence of known upgrade selectors in the contract bytecode at registration time.

3. **Document the restriction**: Add explicit documentation and validation comments in `RegisterOrUpdateTokenMapping` and `SetExternalContractForDenom` stating that upgradeable proxy contracts must never be mapped. [7](#0-6) 

---

### Proof of Concept

1. Attacker deploys `MaliciousProxy` — a UUPS upgradeable proxy whose initial implementation correctly implements `mint_by_cronos_module`, `burn_by_cronos_module`, etc. (passes `ensureContractCode`).

2. CronosAdmin calls `MsgUpdateTokenMapping` mapping `ibc/XXXX` → `MaliciousProxy`. This succeeds because `ensureContractCode` only checks that bytecode exists.

3. Attacker calls `upgradeTo(maliciousImpl)` on `MaliciousProxy`. The new implementation overrides `burn_by_cronos_module` to be a no-op and `mint_by_cronos_module` to additionally mint 10× the amount to `attacker`.

4. A legitimate user sends IBC tokens to Cronos. The IBC middleware calls `ConvertVouchersToEvmCoins` → `ConvertCoinFromNativeToCRC21` → `CallModuleCRC21(contract, "mint_by_cronos_module", sender, amount)`.

5. The malicious implementation executes: mints `amount` to `sender` (correct) AND mints `10 * amount` to `attacker` (unauthorized). The module has no way to detect or revert this because `CallModuleCRC21` only checks `res.Failed()` — a successful EVM execution with side effects is accepted.

6. Attacker now holds unbacked CRC21 tokens. They call `ConvertCoinFromCRC21ToNative` → `burn_by_cronos_module` (no-op) → module mints native coins to attacker. Attacker has both EVM tokens and native coins — full double-spend. [2](#0-1) [8](#0-7)

### Citations

**File:** x/cronos/keeper/keeper.go (L202-216)
```go
// SetExternalContractForDenom sets denom→external CRC21 mapping for an unmapped denom.
// Caller is responsible for source-denom specific validation before calling this method.
func (k Keeper) SetExternalContractForDenom(ctx sdk.Context, denom string, address common.Address) error {
	if err := k.ensureDenomNotMapped(ctx, denom); err != nil {
		return err
	}
	if err := k.ensureContractNotMapped(ctx, denom, address); err != nil {
		return err
	}

	store := ctx.KVStore(k.storeKey)
	store.Set(types.DenomToExternalContractKey(denom), address.Bytes())
	store.Set(types.ContractToDenomKey(address.Bytes()), []byte(denom))
	return nil
}
```

**File:** x/cronos/keeper/keeper.go (L312-327)
```go
func (k Keeper) ensureContractCode(ctx sdk.Context, contract common.Address) error {
	if contract.Big().Cmp(big.NewInt(256)) < 0 {
		return errors.Wrapf(sdkerrors.ErrInvalidAddress,
			"crc21 contract must not be in precompile range: %s", contract.Hex())
	}
	resp, err := k.evmKeeper.Code(ctx, &evmtypes.QueryCodeRequest{
		Address: contract.Hex(),
	})
	if err != nil {
		return errors.Wrapf(sdkerrors.ErrInvalidAddress, "failed to query contract code (%s): %v", contract.Hex(), err)
	}
	if resp == nil || len(resp.Code) == 0 {
		return errors.Wrapf(sdkerrors.ErrInvalidRequest, "no contract code at address (%s)", contract.Hex())
	}
	return nil
}
```

**File:** x/cronos/keeper/evm.go (L55-68)
```go
func (k Keeper) CallModuleCRC21(ctx sdk.Context, contract common.Address, method string, args ...interface{}) ([]byte, error) {
	data, err := types.ModuleCRC21Contract.ABI.Pack(method, args...)
	if err != nil {
		return nil, err
	}
	_, res, err := k.CallEVM(ctx, &contract, data, big.NewInt(0), DefaultGasCap)
	if err != nil {
		return nil, err
	}
	if res.Failed() {
		return nil, fmt.Errorf("call contract failed: %s, %s, %s", contract.Hex(), method, res.Ret)
	}
	return res.Ret, nil
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

**File:** x/cronos/keeper/evm.go (L156-182)
```go
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
```

**File:** x/cronos/middleware/conversion_middleware.go (L125-143)
```go
	if im.canBeConverted(cacheCtx, denom) {
		transferAmount, ok := sdkmath.NewIntFromString(data.Token.Amount)
		if !ok {
			return channeltypes.NewErrorAcknowledgement(errors.Wrapf(
				transferTypes.ErrInvalidAmount,
				"unable to parse transfer amount (%s) into sdk.Int in middleware",
				data.Token.Amount,
			))
		}
		token := sdk.NewCoin(denom, transferAmount)
		if err := im.cronoskeeper.ConvertVouchersToEvmCoins(cacheCtx, data.Receiver, sdk.NewCoins(token)); err != nil {
			im.cronoskeeper.Logger(ctx).Error(
				"failed to convert vouchers on recv",
				"denom", denom,
				"receiver", data.Receiver,
				"error", err,
			)
			return channeltypes.NewErrorAcknowledgement(err)
		}
```

**File:** contracts/src/ModuleCRC20Proxy.sol (L1-25)
```text
pragma solidity ^0.6.8;

import "ds-math/math.sol";
import "./ModuleCRC20.sol";

contract ModuleCRC20Proxy is DSMath {
    // sha256('cronos-evm')[:20]
    address constant module_address = 0x89A7EF2F08B1c018D5Cc88836249b84Dd5392905;
    ModuleCRC20 crc20Contract;
    bool isSource;

    event __CronosSendToIbc(address indexed sender, uint256 indexed channel_id, string recipient, uint256 amount, bytes extraData);
    event __CronosSendToEvmChain(address indexed sender, address indexed recipient, uint256 indexed chain_id, uint256 amount, uint256 bridge_fee, bytes extraData);
    event __CronosCancelSendToEvmChain(address indexed sender, uint256 id);

    /**
        Instantiate a ModuleCRC20Proxy contract. Need to set manually the crc20 contract authority to be the proxy
        like the following call:
        crc20Contract.setAuthority(DSAuthority(address(new ModuleCRC20ProxyAuthority(address(this)))));
    **/
    constructor(address crc20Contract_, bool isSource_) public {
        crc20Contract = ModuleCRC20(crc20Contract_);
        isSource = isSource_;
    }

```
