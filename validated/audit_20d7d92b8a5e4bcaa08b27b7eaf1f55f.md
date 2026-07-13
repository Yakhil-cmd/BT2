### Title
Unpermissioned `MsgConvertVouchers` Can Front-Run Admin Token-Mapping Registration via Auto-Deployment — (File: x/cronos/keeper/msg_server.go)

---

### Summary

When `EnableAutoDeployment` is `true`, any unprivileged user can call `MsgConvertVouchers` to trigger auto-deployment of a `ModuleCRC21` contract for any valid IBC denom they hold. Once the auto contract is stored via `SetAutoContractForDenom`, the denom slot is permanently occupied: the admin's subsequent `MsgUpdateTokenMapping` call fails with `ErrDenomAlreadyMapped` because no `DeleteAutoContractForDenom` path exists. This permanently bypasses the admin's token-mapping authority for the targeted denom.

---

### Finding Description

`MsgConvertVouchers` in `msg_server.go` carries **no permission check**:

```go
func (k msgServer) ConvertVouchers(goCtx context.Context, msg *types.MsgConvertVouchers) (*types.MsgConvertVouchersResponse, error) {
    ctx := sdk.UnwrapSDKContext(goCtx)
    err := k.ConvertVouchersToEvmCoins(ctx, msg.Address, msg.Coins)
``` [1](#0-0) 

Compare this with `UpdateTokenMapping`, which correctly gates on `CanChangeTokenMapping`:

```go
if !k.HasPermission(ctx, msg.GetSigners(), CanChangeTokenMapping) {
    return nil, errors.Wrap(sdkerrors.ErrUnauthorized, "msg sender is not authorized")
}
``` [2](#0-1) 

`ConvertVouchersToEvmCoins` passes `params.EnableAutoDeployment` as the `autoDeploy` flag into `ConvertCoinFromNativeToCRC21`: [3](#0-2) 

When `autoDeploy` is `true` and no contract is mapped yet, `ConvertCoinFromNativeToCRC21` deploys a new `ModuleCRC21` contract and registers it:

```go
contract, err = k.DeployModuleCRC21(ctx, coin.Denom)
...
if err = k.SetAutoContractForDenom(ctx, coin.Denom, contract); err != nil {
``` [4](#0-3) 

`SetAutoContractForDenom` calls `ensureDenomNotMapped`, which checks **both** external and auto contracts via `GetContractByDenom`: [5](#0-4) 

Once an auto contract is stored, `ensureDenomNotMapped` returns `ErrDenomAlreadyMapped` for any subsequent call: [6](#0-5) 

The admin's `RegisterOrUpdateTokenMapping` for non-source denoms calls `SetExternalContractForDenom`, which calls `ensureDenomNotMapped` — and therefore fails: [7](#0-6) 

There is no `DeleteAutoContractForDenom` function anywhere in the keeper. `RegisterOrUpdateTokenMapping` with an empty contract only calls `DeleteExternalContractForDenom`, which does not touch the auto-contract slot: [8](#0-7) 

---

### Impact Explanation

An unprivileged attacker who holds any amount of a target IBC denom can permanently occupy its denom→contract mapping slot before the admin registers an external contract. After the attack:

- The admin's `MsgUpdateTokenMapping` fails with `ErrDenomAlreadyMapped` for that denom — permanently.
- The admin cannot register an external contract with custom symbol, decimals, or security controls (e.g., a blocklist-enforcing contract).
- No on-chain remediation path exists short of a chain upgrade, because `DeleteAutoContractForDenom` does not exist.

This is a **bypass of Cronos admin token-mapping authority** and **corruption of denom/contract binding with direct security impact**, matching the High impact tier.

---

### Likelihood Explanation

- `EnableAutoDeployment` must be `true` (a governance-controlled parameter).
- The attacker must hold a non-zero balance of the target IBC denom.
- The attacker must act before the admin's `MsgUpdateTokenMapping` transaction is included.
- Likelihood is **low** but the window is open for any new IBC denom arriving while auto-deployment is enabled.

---

### Recommendation

Apply one or more of the following:

1. **Add a permission check to `MsgConvertVouchers`** — require `CanChangeTokenMapping` permission when the call would trigger auto-deployment of a new contract.
2. **Add `DeleteAutoContractForDenom`** — expose an admin-only path to remove auto-deployed contracts, restoring the admin's ability to register external contracts.
3. **Allow `SetExternalContractForDenom` to override auto contracts** — distinguish between "already has an external contract" (block) and "only has an auto contract" (allow override by admin).

---

### Proof of Concept

1. Governance sets `EnableAutoDeployment = true`.
2. A new IBC denom `ibc/XXXX` arrives on Cronos; no contract is mapped yet.
3. Admin prepares `MsgUpdateTokenMapping{denom: "ibc/XXXX", contract: "0xCustom..."}`.
4. Attacker, holding 1 `ibc/XXXX` token, broadcasts `MsgConvertVouchers{address: attacker, coins: [{denom: "ibc/XXXX", amount: 1}]}` first.
5. Execution path: `ConvertVouchersToEvmCoins` → `ConvertCoinFromNativeToCRC21(autoDeploy=true)` → `DeployModuleCRC21("ibc/XXXX")` → `SetAutoContractForDenom("ibc/XXXX", autoAddr)`.
6. Admin's `MsgUpdateTokenMapping` executes: `RegisterOrUpdateTokenMapping` → `SetExternalContractForDenom` → `ensureDenomNotMapped` → **returns `ErrDenomAlreadyMapped`**.
7. Admin's transaction fails. The denom is permanently locked to the auto-deployed contract. No on-chain path exists to remove the auto contract.

### Citations

**File:** x/cronos/keeper/msg_server.go (L27-44)
```go
func (k msgServer) ConvertVouchers(goCtx context.Context, msg *types.MsgConvertVouchers) (*types.MsgConvertVouchersResponse, error) {
	ctx := sdk.UnwrapSDKContext(goCtx)
	err := k.ConvertVouchersToEvmCoins(ctx, msg.Address, msg.Coins)
	if err != nil {
		return nil, err
	}

	// emit events
	ctx.EventManager().EmitEvents(sdk.Events{
		types.NewConvertVouchersEvent(msg.Address, msg.Coins),
		sdk.NewEvent(
			sdk.EventTypeMessage,
			sdk.NewAttribute(sdk.AttributeKeyModule, types.ModuleName),
		),
	},
	)

	return &types.MsgConvertVouchersResponse{}, nil
```

**File:** x/cronos/keeper/msg_server.go (L69-82)
```go
func (k msgServer) UpdateTokenMapping(goCtx context.Context, msg *types.MsgUpdateTokenMapping) (*types.MsgUpdateTokenMappingResponse, error) {
	ctx := sdk.UnwrapSDKContext(goCtx)

	// check permission
	if !k.HasPermission(ctx, msg.GetSigners(), CanChangeTokenMapping) {
		return nil, errors.Wrap(sdkerrors.ErrUnauthorized, "msg sender is not authorized")
	}

	// msg is already validated
	if err := k.RegisterOrUpdateTokenMapping(ctx, msg); err != nil {
		return nil, err
	}
	return &types.MsgUpdateTokenMappingResponse{}, nil
}
```

**File:** x/cronos/keeper/ibc.go (L59-64)
```go
		default:
			err := k.ConvertCoinFromNativeToCRC21(ctx, common.BytesToAddress(acc.Bytes()), c, params.EnableAutoDeployment)
			if err != nil {
				return err
			}
		}
```

**File:** x/cronos/keeper/evm.go (L97-111)
```go
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
```

**File:** x/cronos/keeper/keeper.go (L172-182)
```go
func (k Keeper) ensureDenomNotMapped(ctx sdk.Context, denom string) error {
	if contract, found := k.GetContractByDenom(ctx, denom); found {
		return errors.Wrapf(
			types.ErrDenomAlreadyMapped,
			"denom %s is already mapped to contract %s",
			denom,
			contract.Hex(),
		)
	}
	return nil
}
```

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

**File:** x/cronos/keeper/keeper.go (L244-269)
```go
// DeleteExternalContractForDenom delete the external contract mapping for native denom,
// returns false if mapping not exists.
func (k Keeper) DeleteExternalContractForDenom(ctx sdk.Context, denom string) bool {
	store := ctx.KVStore(k.storeKey)
	contract, found := k.getExternalContractByDenom(ctx, denom)
	if !found {
		return false
	}
	store.Delete(types.DenomToExternalContractKey(denom))
	deleteReverseIfOwned(store, contract, denom)
	if auto, found := k.getAutoContractByDenom(ctx, denom); found {
		bz := store.Get(types.ContractToDenomKey(auto.Bytes()))
		if len(bz) == 0 {
			store.Set(types.ContractToDenomKey(auto.Bytes()), []byte(denom))
		} else if existingDenom := string(bz); existingDenom != denom {
			if k.contractOwnedByDenom(ctx, existingDenom, auto) {
				// auto address is already owned by another denom; drop local auto mapping
				store.Delete(types.DenomToAutoContractKey(denom))
			} else {
				// stale reverse entry
				store.Set(types.ContractToDenomKey(auto.Bytes()), []byte(denom))
			}
		}
	}
	return true
}
```

**File:** x/cronos/keeper/keeper.go (L272-287)
```go
func (k Keeper) SetAutoContractForDenom(ctx sdk.Context, denom string, address common.Address) error {
	isSource := types.IsSourceCoin(denom)
	if err := validateContractAddressForSourceDenom(denom, address, isSource); err != nil {
		return err
	}
	if err := k.ensureDenomNotMapped(ctx, denom); err != nil {
		return err
	}
	if err := k.ensureContractNotMapped(ctx, denom, address); err != nil {
		return err
	}
	store := ctx.KVStore(k.storeKey)
	store.Set(types.DenomToAutoContractKey(denom), address.Bytes())
	store.Set(types.ContractToDenomKey(address.Bytes()), []byte(denom))
	return nil
}
```
