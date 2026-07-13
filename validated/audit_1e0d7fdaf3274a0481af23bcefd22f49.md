The code path is fully traceable. Let me lay out the exact analysis.

---

### Title
Stored KV Permissions Persist After `cronos_admin` Is Cleared, Allowing Former Admin to Bypass Governance Revocation — (`x/cronos/keeper/permissions.go`, `x/cronos/keeper/msg_server.go`)

### Summary

`HasPermission` checks KV-stored permissions independently of the current `cronos_admin` value. `UpdateParams` (the governance-gated admin-change path) never clears stored permissions. Once `cronos_admin` is set to empty, `UpdatePermissions` is also permanently locked out (no sender can equal an empty admin). The result: any address previously granted permissions retains them indefinitely, with no on-chain mechanism to revoke them.

### Finding Description

**Step 1 — Admin stores explicit permissions for itself (or any address):**

`UpdatePermissions` checks only that `msg.From == admin`. There is no restriction preventing the admin from targeting its own address: [1](#0-0) 

`SetPermissions` writes a `uint64` bitmask to the KV store under `AdminToPermissionsKey(address)`: [2](#0-1) 

**Step 2 — Governance clears `cronos_admin` via `MsgUpdateParams`:**

`UpdateParams` calls `SetParams` with the new params (including `CronosAdmin: ""`). There is no code that iterates stored permissions and clears them: [3](#0-2) 

**Step 3 — Former admin calls `UpdateTokenMapping`:**

`UpdateTokenMapping` delegates to `HasPermission`: [4](#0-3) 

`HasPermission` first checks `admin == account.String()` (false, admin is now `""`), then falls through to the KV lookup: [5](#0-4) 

The stored bitmask `CanChangeTokenMapping` (value `1`) satisfies `permission & CanChangeTokenMapping == CanChangeTokenMapping`, so `HasPermission` returns `true` and `UpdateTokenMapping` proceeds.

**Permanent lock-out of revocation:**

After `cronos_admin` is set to `""`, `UpdatePermissions` rejects every sender (comment in code: *"if admin is empty, no sender could be equal to it"*): [6](#0-5) 

There is no governance-accessible path to clear individual stored permissions once the admin is empty. The permission grant is irrevocable.

### Impact Explanation

A former admin (or any address previously granted `CanChangeTokenMapping`) can call `UpdateTokenMapping` and arbitrarily remap IBC denom ↔ CRC20 contract bindings after governance has explicitly removed all admin authority. This directly enables token mapping corruption — a listed High impact — and constitutes a bypass of governance authority over the permission system.

### Likelihood Explanation

The precondition (admin grants permissions to itself or to delegatee addresses) is a normal operational pattern described in ADR-009. Governance rotating or clearing the admin is also a documented, expected governance action. The two events composing the precondition are independently routine; their combination is not contrived.

### Recommendation

`SetParams` (or a dedicated hook on `CronosAdmin` change) should iterate all stored permission entries and zero them out whenever `CronosAdmin` changes. Alternatively, `HasPermission` should short-circuit the KV lookup when `CronosAdmin` is empty, treating the absence of an admin as a full permission freeze.

### Proof of Concept

State-transition unit test (no live chain needed):

```go
// 1. Set admin to addrA
params.CronosAdmin = addrA.String()
keeper.SetParams(ctx, params)

// 2. Admin grants itself CanChangeTokenMapping
keeper.SetPermissions(ctx, addrA, CanChangeTokenMapping)

// 3. Governance clears admin
params.CronosAdmin = ""
keeper.SetParams(ctx, params)

// 4. Former admin calls UpdateTokenMapping — must fail, but passes
assert.True(t, keeper.HasPermission(ctx, []sdk.AccAddress{addrA}, CanChangeTokenMapping))
// HasPermission returns true via KV lookup, not via admin check
// UpdateTokenMapping proceeds and corrupts token mappings
```

### Citations

**File:** x/cronos/keeper/msg_server.go (L72-75)
```go
	// check permission
	if !k.HasPermission(ctx, msg.GetSigners(), CanChangeTokenMapping) {
		return nil, errors.Wrap(sdkerrors.ErrUnauthorized, "msg sender is not authorized")
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

**File:** x/cronos/keeper/permissions.go (L37-46)
```go
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
```
