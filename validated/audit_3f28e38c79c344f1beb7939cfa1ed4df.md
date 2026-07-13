### Title
`CanTurnBridge` Permission Stored in State but Never Enforced — `TurnBridge` Handler is a Silent No-Op - (File: x/cronos/keeper/msg_server.go)

### Summary
The `CanTurnBridge` permission bit is defined, stored in the KV store via `MsgUpdatePermissions`, and returned by the `Permissions` query — but the `TurnBridge` message handler unconditionally returns `nil, nil` without checking the permission or performing any state change. Any unprivileged caller can invoke `MsgTurnBridge` and receive a success response. The bridge on/off control mechanism is permanently non-functional.

### Finding Description
`permissions.go` defines two permission bits: `CanChangeTokenMapping` (bit 0) and `CanTurnBridge` (bit 1). [1](#0-0) 

`MsgUpdatePermissions` (admin-only) stores these bits in the KV store under `prefixAdminToPermissions`. [2](#0-1) 

`HasPermission` correctly reads and checks the stored bits. [3](#0-2) 

`UpdateTokenMapping` correctly gates on `CanChangeTokenMapping`:
```go
if !k.HasPermission(ctx, msg.GetSigners(), CanChangeTokenMapping) {
    return nil, errors.Wrap(sdkerrors.ErrUnauthorized, "msg sender is not authorized")
}
``` [4](#0-3) 

However, `TurnBridge` is a complete no-op:
```go
func (k msgServer) TurnBridge(goCtx context.Context, msg *types.MsgTurnBridge) (*types.MsgTurnBridgeResponse, error) {
    return nil, nil
}
``` [5](#0-4) 

It neither checks `HasPermission(..., CanTurnBridge)` nor performs any state mutation. The `CanTurnBridge` permission stored in `prefixAdminToPermissions` is never read by any production handler. [6](#0-5) 

The `Permissions` query does surface `CanTurnBridge` to callers, reinforcing the expectation that it is enforced. [7](#0-6) 

ADR-009 explicitly designates `MsgTurnBridge` as a permissioned message that must be restricted to a specific group policy address. [8](#0-7) 

### Impact Explanation
**High — Bypass of bridge authorization checks.**

1. The bridge on/off control is permanently non-functional. No actor — including the Cronos admin — can turn the bridge off via the intended `MsgTurnBridge` path.
2. Any unprivileged address can submit `MsgTurnBridge` and receive a success response (`nil` error), bypassing the `CanTurnBridge` permission gate entirely.
3. The `CanTurnBridge` permission is stored in state (analogous to the external `flaggedNFTS` mapping) but is never read in the actual enforcement path, making the entire permission system for bridge control inert.

This matches: **High: Bypass of Cronos admin, governance authority, permission, token-mapping, bridge, block-list, or module-account authorization checks.**

### Likelihood Explanation
Certain. The handler is unconditionally `return nil, nil`. No code path through `TurnBridge` can ever check or enforce `CanTurnBridge`. Any user who submits a `MsgTurnBridge` transaction will receive a success response.

### Recommendation
Implement `TurnBridge` to:
1. Check `HasPermission(ctx, msg.GetSigners(), CanTurnBridge)` and return `ErrUnauthorized` on failure.
2. Perform the intended bridge state mutation (e.g., toggling `enable_auto_deployment` or a dedicated bridge-enabled parameter).

If the bridge-turn functionality is intentionally removed, the `CanTurnBridge` permission constant, the `MsgTurnBridge` message type, and the `prefixAdminToPermissions` entries for that bit should be deprecated and removed to avoid misleading operators and auditors.

### Proof of Concept
1. Any address submits `MsgTurnBridge{From: <any_address>, Enable: false}`.
2. The handler at `msg_server.go:85` executes `return nil, nil`.
3. The transaction succeeds on-chain with no state change and no permission check.
4. The bridge remains in its current state regardless of the submitted value.
5. Separately, the Cronos admin calls `MsgUpdatePermissions` to grant `CanTurnBridge` to a trusted address — the stored permission is never read by `TurnBridge`, so the grant is meaningless.

### Citations

**File:** x/cronos/keeper/permissions.go (L13-17)
```go
const (
	CanChangeTokenMapping uint64                                  = 1 << iota // 1
	CanTurnBridge                                                             // 2
	All                   = CanChangeTokenMapping | CanTurnBridge             // 3
)
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

**File:** x/cronos/keeper/msg_server.go (L84-87)
```go
// TurnBridge implements the grpc method
func (k msgServer) TurnBridge(goCtx context.Context, msg *types.MsgTurnBridge) (*types.MsgTurnBridgeResponse, error) {
	return nil, nil
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

**File:** x/cronos/types/keys.go (L29-30)
```go
	prefixAdminToPermissions
	prefixBlockList
```

**File:** x/cronos/keeper/grpc_query.go (L123-145)
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
}
```

**File:** docs/architecture/adr-009.md (L61-68)
```markdown
- The policy is associated to a group policy address, each permissioned msg within the proposal needs to be originated from the group policy address (TBD)
- To be abe to execute a permissioned msg, one member of the group needs to send the msg ``Msg/SubmitProposal``

In Cronos module, we need to restrict ``MsgUpdateTokenMapping`` and ``MsgTurnBridge`` msg to only specific "group policy address".

- Store in the state a mapping between msg and group policy address that are allowed to trigger the msg
- Only a governance proposal to be able to change the mapping
- Add code to check the sender address of the message and reject it if it does not belong to one of the address defined in the mapping
```
