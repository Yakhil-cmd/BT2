### Title
Stale Per-Address Permissions Persist After `CronosAdmin` Rotation, Bypassing New Admin Authority - (File: x/cronos/keeper/permissions.go)

### Summary
When governance rotates `CronosAdmin` via `MsgUpdateParams`, the per-address permission entries previously written to the KVStore by the old admin are never cleared. `HasPermission` reads those stale KVStore entries and grants them the same weight as entries written by the current admin, allowing an address that was authorized only by the old admin to continue calling `MsgUpdateTokenMapping` and `MsgTurnBridge` indefinitely.

### Finding Description

`CronosAdmin` is a governance-updatable parameter stored in `Params`: [1](#0-0) 

It is persisted and replaced atomically by `SetParams`: [2](#0-1) 

Separately, the old admin can grant fine-grained permissions to arbitrary addresses via `MsgUpdatePermissions`, which writes a bitmask into a distinct KVStore prefix: [3](#0-2) 

`HasPermission` — the gate for every restricted message — reads both the current `CronosAdmin` param **and** the per-address KVStore entries: [4](#0-3) 

`SetParams` only overwrites `ParamsKey`; it never touches `KeyPrefixAdminToPermissions`: [2](#0-1) 

There is no hook, migration, or event handler that clears the per-address permission entries when `CronosAdmin` changes. The new admin has no enumeration API to discover which addresses hold stale permissions; the only query is `Permissions(address)` for a single known address: [5](#0-4) 

This is the direct Cronos analog of the external report: `CoreRef._vcon` was an immutable cached copy that diverged from `Core.vcon` after a governor update. Here, the per-address permission entries are a persistent cached copy of the old admin's authorization decisions that diverge from the new admin's intent after a governance-driven `CronosAdmin` rotation.

### Impact Explanation

An address X that was granted `CanChangeTokenMapping` (bit 1) or `CanTurnBridge` (bit 2) by the old admin retains those bits in KVStore after the admin rotates. `HasPermission` will return `true` for X on every subsequent call: [6](#0-5) 

With `CanChangeTokenMapping`, X can call `MsgUpdateTokenMapping` with an empty `contract` field to **delete** existing denom→contract mappings: [7](#0-6) 

Deleting a mapping breaks `ConvertVouchersToEvmCoins` and `canBeConverted` for that denom, permanently blocking IBC-to-EVM conversion for all holders of that token until the new admin re-registers the mapping. [8](#0-7) 

With `CanTurnBridge`, X can disable the bridge entirely, causing a long-lived inability for all users to process bridge/conversion flows.

Both outcomes satisfy the High impact criteria: bypass of admin/permission authorization checks, corruption of token mappings with direct security impact, and permanent inability for honest users to process bridge/conversion flows.

### Likelihood Explanation

The scenario is realistic: governance rotates `CronosAdmin` precisely when the old admin is suspected of compromise or when operational control is being transferred. The old admin may have granted `CanChangeTokenMapping` or `CanTurnBridge` to one or more addresses (e.g., automated relayers, circuit-breaker bots) that are now adversarial or simply no longer trusted. Because there is no enumeration API for permissioned addresses and no automatic revocation, the new admin cannot easily discover or revoke stale entries before they are exploited. The attacker needs no privileged access under the new regime — only the stale KVStore entry written by the old admin.

### Recommendation

`SetParams` should detect a `CronosAdmin` change and clear all per-address permission entries, or alternatively emit an on-chain event that forces an explicit revocation step. A minimal fix is to iterate `KeyPrefixAdminToPermissions` and delete every entry inside `SetParams` whenever `params.CronosAdmin` differs from the currently stored value. Additionally, expose a gRPC query that enumerates all addresses with non-zero permissions so that a new admin can audit and revoke stale grants.

### Proof of Concept

1. Governance sets `CronosAdmin = Alice`.
2. Alice calls `MsgUpdatePermissions(address=Mallory, permissions=3)` — granting Mallory both `CanChangeTokenMapping` and `CanTurnBridge`.
3. Governance passes `MsgUpdateParams` setting `CronosAdmin = Bob` (e.g., because Alice's key was compromised).
4. `SetParams` writes the new `Params` blob to `ParamsKey` but does not touch `KeyPrefixAdminToPermissions`.
5. Mallory calls `MsgUpdateTokenMapping(denom="ibc/...", contract="")`.
6. `HasPermission` reads `GetParams(ctx).CronosAdmin == "Bob"` (≠ Mallory), then reads `GetPermissions(ctx, Mallory) == 3`, finds `3 & 1 == 1`, and returns `true`.
7. `RegisterOrUpdateTokenMapping` deletes the denom→contract mapping for the IBC token.
8. All subsequent `OnRecvVouchers` calls for that denom fail — IBC-to-EVM conversion is broken for all users of that token. [4](#0-3) [2](#0-1) [9](#0-8)

### Citations

**File:** x/cronos/types/cronos.pb.go (L31-31)
```go
	CronosAdmin          string `protobuf:"bytes,3,opt,name=cronos_admin,json=cronosAdmin,proto3" json:"cronos_admin,omitempty"`
```

**File:** x/cronos/keeper/params.go (L27-37)
```go
func (k Keeper) SetParams(ctx sdk.Context, params types.Params) error {
	if err := params.Validate(); err != nil {
		return err
	}

	store := ctx.KVStore(k.storeKey)
	bz := k.cdc.MustMarshal(&params)
	store.Set(types.ParamsKey, bz)

	return nil
}
```

**File:** x/cronos/keeper/permissions.go (L19-23)
```go
func (k Keeper) SetPermissions(ctx sdk.Context, address sdk.AccAddress, permissions uint64) {
	store := ctx.KVStore(k.storeKey)
	permissionsBytes := sdk.Uint64ToBigEndian(permissions)
	store.Set(types.AdminToPermissionsKey(address), permissionsBytes)
}
```

**File:** x/cronos/keeper/permissions.go (L32-48)
```go
func (k Keeper) HasPermission(ctx sdk.Context, accounts []sdk.AccAddress, permissionsToCheck uint64) bool {
	// case when no permission is needed
	if permissionsToCheck == 0 {
		return true
	}
	admin := k.GetParams(ctx).CronosAdmin
	for _, account := range accounts {
		if admin == account.String() {
			return true
		}
		permission := k.GetPermissions(ctx, account)
		if permission&permissionsToCheck == permissionsToCheck {
			return true
		}
	}

	return false
```

**File:** x/cronos/keeper/grpc_query.go (L123-144)
```go
// Permissions returns the permissions of a specific account
func (k Keeper) Permissions(goCtx context.Context, req *types.QueryPermissionsRequest) (*types.QueryPermissionsResponse, error) {
	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "empty request")
	}
	ctx := sdk.UnwrapSDKContext(goCtx)
	acc, err := sdk.AccAddressFromBech32(req.Address)
	if err != nil {
		return nil, err
	}
	admin := k.GetParams(ctx).CronosAdmin
	if admin == acc.String() {
		return &types.QueryPermissionsResponse{
			CanChangeTokenMapping: true,
			CanTurnBridge:         true,
		}, nil
	}
	permissions := k.GetPermissions(ctx, acc)
	return &types.QueryPermissionsResponse{
		CanChangeTokenMapping: CanChangeTokenMapping == (permissions & CanChangeTokenMapping),
		CanTurnBridge:         CanTurnBridge == (permissions & CanTurnBridge),
	}, nil
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

**File:** x/cronos/middleware/conversion_middleware.go (L256-263)
```go
func (im IBCConversionModule) canBeConverted(ctx sdk.Context, denom string) bool {
	params := im.cronoskeeper.GetParams(ctx)
	if denom == params.IbcCroDenom {
		return true
	}
	_, found := im.cronoskeeper.GetContractByDenom(ctx, denom)
	return found
}
```
