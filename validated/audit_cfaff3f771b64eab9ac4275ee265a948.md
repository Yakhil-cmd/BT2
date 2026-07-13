### Title
Stale Delegated Permissions Persist After `CronosAdmin` Rotation, Bypassing New Admin Authority Over Token Mappings - (File: x/cronos/keeper/msg_server.go, x/cronos/keeper/permissions.go)

### Summary
When governance rotates the `CronosAdmin` address via `MsgUpdateParams`, all per-address permissions previously granted by the old admin via `MsgUpdatePermissions` remain permanently active in the KV store. Those addresses can continue to call `MsgUpdateTokenMapping` (and `MsgTurnBridge` once implemented) under the new admin regime without any authorization from the new admin, bypassing the intended access-control boundary.

### Finding Description

Cronos implements a two-layer permission system:

1. **`CronosAdmin`** — a single address stored in module params, changeable only by governance via `MsgUpdateParams` → `SetParams`.
2. **Delegated permissions** — per-address bitmask entries (`CanChangeTokenMapping = 1`, `CanTurnBridge = 2`) stored in the KV store under `AdminToPermissionsKey(address)`, writable only by the current `CronosAdmin` via `MsgUpdatePermissions`.

`HasPermission` grants access if either the account equals the current `CronosAdmin` **or** the account has a non-zero stored permission bitmask:

```go
// x/cronos/keeper/permissions.go:32-48
func (k Keeper) HasPermission(...) bool {
    admin := k.GetParams(ctx).CronosAdmin
    for _, account := range accounts {
        if admin == account.String() { return true }
        permission := k.GetPermissions(ctx, account)
        if permission&permissionsToCheck == permissionsToCheck { return true }
    }
    return false
}
```

`SetParams` (called by `UpdateParams`) only marshals and stores the new params blob — it performs no cleanup of the delegated-permissions KV namespace:

```go
// x/cronos/keeper/params.go:27-37
func (k Keeper) SetParams(ctx sdk.Context, params types.Params) error {
    if err := params.Validate(); err != nil { return err }
    store := ctx.KVStore(k.storeKey)
    bz := k.cdc.MustMarshal(&params)
    store.Set(types.ParamsKey, bz)
    return nil
}
```

There is no hook, migration, or cleanup step that iterates over `KeyPrefixAdminToPermissions` entries and zeroes them when `CronosAdmin` changes. The new admin has no way to enumerate which addresses hold stale permissions (no list/iterator is exposed), making silent revocation impossible.

### Impact Explanation

An address X that was granted `CanChangeTokenMapping` by old Admin A retains that permission after governance rotates `CronosAdmin` to Admin B. X can call `MsgUpdateTokenMapping`, which passes the `HasPermission` check and reaches `RegisterOrUpdateTokenMapping`. This allows X to:

- Register new denom→contract mappings for previously unmapped denoms, corrupting the token-mapping state used by IBC conversion and bridge hooks.
- Delete existing non-source-token mappings (by passing an empty contract), breaking bridge/conversion flows for those tokens.

This is a **High** impact: bypass of Cronos admin/governance authority over token-mapping and bridge authorization checks, with direct potential for corruption of denom/contract bindings that underpin IBC voucher conversion and gravity bridge accounting.

### Likelihood Explanation

The trigger requires two sequential events: (1) the current admin grants delegated permissions to one or more addresses, and (2) governance later rotates `CronosAdmin`. Both are normal operational events. The old admin or any previously-trusted address that turns adversarial after rotation can exploit this immediately — no additional privileges, leaked keys, or cryptographic breaks are needed. The new admin has no automated notification or enumeration tool to discover and revoke stale entries.

### Recommendation

In `UpdateParams` (or in `SetParams`), when `CronosAdmin` changes, iterate over all `KeyPrefixAdminToPermissions` entries and delete them before writing the new params. Alternatively, store a "permissions epoch" counter alongside params and include it in the permission key, so that all permissions granted under a prior epoch are automatically invalidated on admin rotation without requiring explicit enumeration.

### Proof of Concept

1. Governance sets `CronosAdmin = AdminA` via `MsgUpdateParams`.
2. `AdminA` calls `MsgUpdatePermissions{from: AdminA, address: AdversaryX, permissions: 3}` — grants `AdversaryX` both `CanChangeTokenMapping` and `CanTurnBridge`.
3. Governance rotates admin: `MsgUpdateParams{params: {CronosAdmin: AdminB, ...}}`. `SetParams` writes new params; `AdminToPermissionsKey(AdversaryX)` entry is untouched.
4. `AdversaryX` submits `MsgUpdateTokenMapping{sender: AdversaryX, denom: "gravity0x<newContract>", contract: "<newContract>"}`.
5. `UpdateTokenMapping` calls `HasPermission(ctx, [AdversaryX], CanChangeTokenMapping)`. `AdversaryX != AdminB`, but `GetPermissions(ctx, AdversaryX)` returns `3`, so `3 & 1 == 1` → returns `true`.
6. `RegisterOrUpdateTokenMapping` executes, registering a malicious or incorrect denom→contract mapping under the new admin's regime without `AdminB`'s knowledge or consent. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5)

### Citations

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

**File:** x/cronos/keeper/msg_server.go (L68-82)
```go
// UpdateTokenMapping implements the grpc method
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

**File:** x/cronos/keeper/msg_server.go (L89-99)
```go
func (k msgServer) UpdateParams(goCtx context.Context, msg *types.MsgUpdateParams) (*types.MsgUpdateParamsResponse, error) {
	if msg.Authority != k.authority {
		return nil, errors.Wrapf(govtypes.ErrInvalidSigner, "invalid authority; expected %s, got %s", k.authority, msg.Authority)
	}

	ctx := sdk.UnwrapSDKContext(goCtx)
	if err := k.SetParams(ctx, msg.Params); err != nil {
		return nil, err
	}

	return &types.MsgUpdateParamsResponse{}, nil
```

**File:** x/cronos/keeper/msg_server.go (L102-116)
```go
func (k msgServer) UpdatePermissions(goCtx context.Context, msg *types.MsgUpdatePermissions) (*types.MsgUpdatePermissionsResponse, error) {
	ctx := sdk.UnwrapSDKContext(goCtx)
	admin := k.Keeper.GetParams(ctx).CronosAdmin
	// if admin is empty, no sender could be equal to it
	if admin != msg.From {
		return nil, errors.Wrap(sdkerrors.ErrUnauthorized, "msg sender is not authorized")
	}
	acc, err := sdk.AccAddressFromBech32(msg.Address)
	if err != nil {
		return nil, err
	}
	k.SetPermissions(ctx, acc, msg.Permissions)

	return &types.MsgUpdatePermissionsResponse{}, nil
}
```

**File:** x/cronos/types/keys.go (L29-41)
```go
	prefixAdminToPermissions
	prefixBlockList
)

// KVStore key prefixes
var (
	KeyPrefixDenomToExternalContract = []byte{prefixDenomToExternalContract}
	KeyPrefixDenomToAutoContract     = []byte{prefixDenomToAutoContract}
	KeyPrefixContractToDenom         = []byte{prefixContractToDenom}
	// ParamsKey is the key for params.
	ParamsKey                   = []byte{paramsKey}
	KeyPrefixAdminToPermissions = []byte{prefixAdminToPermissions}
	KeyPrefixBlockList          = []byte{prefixBlockList}
```
