The vulnerability claim is real and concrete. Let me trace through the exact code path.

**Step 1: Old admin grants permission to `addr_A`**

`UpdatePermissions` in `msg_server.go` checks `admin == msg.From` and calls `SetPermissions`, which writes the bitmask to the KV store keyed by `addr_A`'s address: [1](#0-0) [2](#0-1) 

**Step 2: Governance rotates `CronosAdmin` to `new_admin`**

`UpdateParams` only updates the params blob in the KV store. It does **not** touch any stored permission bitmasks: [3](#0-2) [4](#0-3) 

**Step 3: `addr_A` calls `MsgUpdateTokenMapping`**

`HasPermission` performs two independent checks — admin string equality, then bitmask lookup: [5](#0-4) 

After rotation, `admin == account.String()` is false for `addr_A`, but `GetPermissions(ctx, addr_A)` still returns the previously stored bitmask (e.g., `1` for `CanChangeTokenMapping`). The bitmask check `permission & permissionsToCheck == permissionsToCheck` passes, so `HasPermission` returns `true` and `UpdateTokenMapping` succeeds: [6](#0-5) 

---

### Title
Stale Permission Bitmasks Survive Admin Rotation, Allowing Revoked Addresses to Corrupt Token Mappings — (`x/cronos/keeper/permissions.go`, `x/cronos/keeper/msg_server.go`)

### Summary
When `CronosAdmin` is rotated via `MsgUpdateParams`, all previously granted per-address permission bitmasks remain in the KV store. `HasPermission` checks the admin string first, then falls through to the stored bitmask. An address that was granted `CanChangeTokenMapping` by the old admin retains that capability indefinitely after the rotation, because no code path clears stored permissions on admin change.

### Finding Description
`SetPermissions` writes a `uint64` bitmask to `AdminToPermissionsKey(address)` in the module KV store. `MsgUpdateParams` / `SetParams` only serializes and stores the `Params` proto (which contains `CronosAdmin`) — it never iterates or clears the permissions sub-store. `HasPermission` is a two-branch OR: admin-string match OR bitmask match. After rotation, the first branch fails for old permissioned addresses, but the second branch succeeds because the bitmask is untouched.

### Impact Explanation
`MsgUpdateTokenMapping` → `RegisterOrUpdateTokenMapping` can overwrite the denom-to-contract binding for any token. An address that should have been de-authorized after an admin rotation can still call this, corrupting token mappings and potentially redirecting conversion flows to attacker-controlled contracts. This falls under **High: Bypass of permission/authorization checks** and **High: Corruption of token mappings with direct security impact**.

### Likelihood Explanation
The scenario is reachable without any key compromise:
1. Old admin legitimately grants `CanChangeTokenMapping` to `addr_A` (normal operation).
2. Governance passes a `MsgUpdateParams` proposal rotating `CronosAdmin` (normal governance operation, any address can submit a proposal).
3. `addr_A` immediately calls `MsgUpdateTokenMapping` — succeeds because the bitmask is still set.

There is no atomic "revoke all + rotate" operation. The new admin must know every previously permissioned address and explicitly call `MsgUpdatePermissions` for each one. During that window, old permissioned addresses retain full write access to token mappings.

### Recommendation
In `SetParams` (or in a dedicated `RotateAdmin` handler), iterate all stored permission entries and zero them out whenever `CronosAdmin` changes. Alternatively, scope stored permissions to the admin address that granted them (e.g., key = `(admin_addr, permissioned_addr)`) so that a change in `CronosAdmin` automatically invalidates all grants made by the previous admin.

### Proof of Concept
```
1. Set CronosAdmin = old_admin in params.
2. old_admin sends MsgUpdatePermissions{from: old_admin, address: addr_A, permissions: 1 (CanChangeTokenMapping)}.
   → k.SetPermissions(ctx, addr_A, 1) writes bitmask=1 to store.
3. Governance passes MsgUpdateParams{authority: gov, params: {cronos_admin: new_admin, ...}}.
   → k.SetParams writes new Params; permissions store is untouched.
4. addr_A sends MsgUpdateTokenMapping{sender: addr_A, denom: "ibc/...", contract: "0xAttacker"}.
   → HasPermission: admin="new_admin" ≠ addr_A (branch 1 fails).
   → GetPermissions(addr_A) = 1; 1 & 1 == 1 → returns true (branch 2 passes).
   → RegisterOrUpdateTokenMapping executes, mapping corrupted.
```

### Citations

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

**File:** x/cronos/keeper/msg_server.go (L89-100)
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
}
```

**File:** x/cronos/keeper/msg_server.go (L102-115)
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
