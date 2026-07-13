### Title
Unprivileged `MsgConvertVouchers` Caller Permanently Blocks Admin External Token-Mapping Registration via Auto-Deployment Race - (`x/cronos/keeper/keeper.go`, `x/cronos/keeper/evm.go`, `x/cronos/keeper/msg_server.go`)

### Summary

When `EnableAutoDeployment=true`, any unprivileged user holding IBC/gravity tokens can call `MsgConvertVouchers` to trigger auto-deployment of a `ModuleCRC21` contract for a denom. The `ensureDenomNotMapped` guardrail in both `SetAutoContractForDenom` and `SetExternalContractForDenom` then permanently prevents the admin from ever registering a custom external contract for that denom, bypassing admin authority over token mapping with no recovery path.

### Finding Description

**Root cause — two interacting code paths:**

**(1) `MsgConvertVouchers` has no permission check and triggers auto-deployment:** [1](#0-0) 

The handler calls `ConvertVouchersToEvmCoins` directly with no caller authorization check. Inside, for any non-CRO denom: [2](#0-1) 

This calls `ConvertCoinFromNativeToCRC21` with `autoDeploy = params.EnableAutoDeployment`. When no contract exists and `autoDeploy=true`, the module deploys its own `ModuleCRC21` bytecode and registers it: [3](#0-2) 

**(2) `ensureDenomNotMapped` permanently blocks subsequent external-contract registration:**

`SetAutoContractForDenom` calls `ensureDenomNotMapped`: [4](#0-3) 

`SetExternalContractForDenom` — the only path the admin uses to register a custom contract — also calls `ensureDenomNotMapped`: [5](#0-4) 

`ensureDenomNotMapped` checks `GetContractByDenom`, which returns `true` for **both** auto and external contracts: [6](#0-5) [7](#0-6) 

There is no `DeleteAutoContractForDenom` function. `DeleteExternalContractForDenom` only removes the external mapping: [8](#0-7) 

`RegisterOrUpdateTokenMapping` with an empty contract string calls `DeleteExternalContractForDenom` — it cannot clear an auto-contract: [9](#0-8) 

The spec confirms this is permanent: *"There's no way to delete a token mapping currently."* [10](#0-9) 

### Impact Explanation

Once an attacker triggers auto-deployment for a target denom, the admin's `MsgUpdateTokenMapping` call fails with `ErrDenomAlreadyMapped` permanently. This is a **High** impact: **Bypass of Cronos admin token-mapping authorization**. Concrete harm:

- A project that has already deployed a custom CRC20 contract on Cronos (with existing liquidity, users, or specific access controls) and intends to register it as the external contract for an IBC denom is permanently blocked from doing so.
- All future IBC inflows for that denom are routed to the auto-deployed contract instead of the intended external one, fragmenting token supply and stranding liquidity in the custom contract.
- The admin has no recovery path: no delete-auto function exists, and governance cannot override the `ErrDenomAlreadyMapped` guard.

### Likelihood Explanation

- **Precondition:** `EnableAutoDeployment=true` (a governance-settable parameter, enabled in production configs).
- **Attacker cost:** Must hold a small amount of the target IBC/gravity tokens — a low bar for any user who has received bridged tokens.
- **Window:** Any time before the admin registers the external contract for a new denom.
- **No special privileges required:** `MsgConvertVouchers` is open to all signers. [11](#0-10) 

### Recommendation

Decouple the "create-only" guardrail from the auto-vs-external distinction. Specifically:

1. **Allow admin to override an auto-contract with an external one.** In `SetExternalContractForDenom`, check only `getExternalContractByDenom` (not `GetContractByDenom`) so that an existing auto-contract does not block external registration. When an external contract is set, the auto-contract entry should be retired (or kept as a fallback).
2. **Alternatively, add `DeleteAutoContractForDenom`** callable only by the admin/governance, so the admin can clear an auto-mapping before registering an external one.
3. **Or restrict `MsgConvertVouchers` auto-deployment** to only trigger if no admin-intended external contract is pending (e.g., require admin pre-approval for new denom mappings before auto-deployment is allowed).

### Proof of Concept

```
// Precondition: EnableAutoDeployment=true, no contract mapped for denom X yet.

// Step 1: Attacker acquires a small amount of IBC denom X (e.g., via IBC transfer).

// Step 2: Attacker submits MsgConvertVouchers — no permission check.
MsgConvertVouchers{Address: attacker, Coins: [{Denom: "ibc/X...", Amount: 1}]}
// → ConvertVouchersToEvmCoins → ConvertCoinFromNativeToCRC21(autoDeploy=true)
// → DeployModuleCRC21 → SetAutoContractForDenom("ibc/X...", autoAddr)
// State: DenomToAutoContract["ibc/X..."] = autoAddr  ✓

// Step 3: Admin attempts to register custom external contract.
MsgUpdateTokenMapping{Sender: admin, Denom: "ibc/X...", Contract: "0xCustom..."}
// → RegisterOrUpdateTokenMapping → SetExternalContractForDenom
// → ensureDenomNotMapped → GetContractByDenom finds autoAddr
// → returns ErrDenomAlreadyMapped  ✗  PERMANENT

// Step 4: Admin attempts to clear mapping (empty contract).
MsgUpdateTokenMapping{Sender: admin, Denom: "ibc/X...", Contract: ""}
// → DeleteExternalContractForDenom — no external contract exists, returns false
// Auto-contract remains.  ✗  NO RECOVERY PATH
```

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

**File:** x/cronos/keeper/ibc.go (L59-63)
```go
		default:
			err := k.ConvertCoinFromNativeToCRC21(ctx, common.BytesToAddress(acc.Bytes()), c, params.EnableAutoDeployment)
			if err != nil {
				return err
			}
```

**File:** x/cronos/keeper/evm.go (L97-110)
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
```

**File:** x/cronos/keeper/keeper.go (L114-120)
```go
func (k Keeper) GetContractByDenom(ctx sdk.Context, denom string) (contract common.Address, found bool) {
	contract, found = k.getExternalContractByDenom(ctx, denom)
	if !found {
		contract, found = k.getAutoContractByDenom(ctx, denom)
	}
	return contract, found
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

**File:** x/cronos/keeper/keeper.go (L204-216)
```go
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

**File:** x/cronos/keeper/keeper.go (L384-401)
```go
	} else {
		if len(msg.Contract) == 0 {
			// delete existing mapping
			k.DeleteExternalContractForDenom(ctx, msg.Denom)
		} else {
			if !common.IsHexAddress(msg.Contract) {
				return errors.Wrapf(sdkerrors.ErrInvalidAddress, "invalid contract address (%s)", msg.Contract)
			}
			// update the mapping
			contract := common.HexToAddress(msg.Contract)
			if err := k.ensureContractCode(ctx, contract); err != nil {
				return err
			}
			if err := k.SetExternalContractForDenom(ctx, msg.Denom, contract); err != nil {
				return err
			}
		}
	}
```

**File:** x/cronos/spec/03_state_transitions.md (L28-30)
```markdown
### Delete

There's no way to delete a token mapping currently.
```
