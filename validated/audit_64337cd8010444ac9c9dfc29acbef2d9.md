### Title
Missing `CanTurnBridge` Permission Check and Empty Implementation in `TurnBridge` Permanently Breaks Bridge Emergency Shutdown - (File: x/cronos/keeper/msg_server.go)

### Summary
The `TurnBridge` message handler in `x/cronos/keeper/msg_server.go` is completely unimplemented: it returns `nil, nil` unconditionally, performing no permission check and no state mutation. ADR-009 explicitly designates `MsgTurnBridge` as one of the two messages requiring the `CanTurnBridge` permission, and the permission infrastructure (`HasPermission`, `CanTurnBridge` constant) exists for exactly this purpose. Any unprivileged user can call `MsgTurnBridge` and receive a success response, while the bridge state is never modified, permanently breaking the emergency bridge shutdown mechanism.

### Finding Description
ADR-009 states: *"there are only two messages that require permission: `MsgUpdateTokenMapping` and `MsgTurnBridge`"* and *"Change the logic to always check for the permission before processing the restricted messages."*

`UpdateTokenMapping` correctly enforces this:

```go
// x/cronos/keeper/msg_server.go:68-82
func (k msgServer) UpdateTokenMapping(...) {
    if !k.HasPermission(ctx, msg.GetSigners(), CanChangeTokenMapping) {
        return nil, errors.Wrap(sdkerrors.ErrUnauthorized, "msg sender is not authorized")
    }
    ...
}
```

`TurnBridge`, however, is:

```go
// x/cronos/keeper/msg_server.go:84-87
func (k msgServer) TurnBridge(goCtx context.Context, msg *types.MsgTurnBridge) (*types.MsgTurnBridgeResponse, error) {
    return nil, nil
}
```

The `CanTurnBridge` permission bit is defined in `x/cronos/keeper/permissions.go` and `HasPermission` supports checking it, but the handler never calls either. The function:
1. Performs no `CanTurnBridge` permission check
2. Performs no state mutation (bridge enable/disable state is never written)
3. Returns success (`nil, nil`) for any caller, including unprivileged ones

The integration test `test_gravity_turn_bridge` asserts `cli.turn_bridge("false", from_="community")` should return `code != 0`, but the live handler returns success for everyone.

### Impact Explanation
**High — Bypass of bridge permission authorization check**: Any unprivileged user can submit `MsgTurnBridge` and receive a success response, bypassing the `CanTurnBridge` permission gate mandated by ADR-009 and enforced by `HasPermission`.

**High — Permanent inability to halt bridge/conversion flows**: The Gravity bridge emergency shutdown mechanism is permanently broken. Even the admin or a permissioned address holding `CanTurnBridge` cannot disable the bridge, because the handler performs no state mutation. In an emergency (e.g., bridge exploit, oracle manipulation), operators have no on-chain mechanism to halt bridge/conversion flows via `MsgTurnBridge`.

### Likelihood Explanation
The missing permission check is reachable by any user who can submit a standard Cosmos SDK transaction to the `cronos.Msg/TurnBridge` endpoint — no privilege required. The broken implementation is a permanent, deterministic condition in the current codebase.

### Recommendation
Implement `TurnBridge` with:
1. A `HasPermission(ctx, msg.GetSigners(), CanTurnBridge)` check mirroring `UpdateTokenMapping`
2. The actual bridge enable/disable state mutation (writing the bridge-enabled flag to the KV store and propagating to the Gravity bridge module)

### Proof of Concept
1. Unprivileged attacker submits `MsgTurnBridge{Sender: <any_address>, Enable: false}`
2. Handler at `msg_server.go:85-87` returns `nil, nil` — success — without checking `CanTurnBridge`
3. No state change occurs; bridge remains enabled
4. Admin submits `MsgTurnBridge{Sender: <admin_address>, Enable: false}` — also returns `nil, nil` with no effect
5. Bridge cannot be disabled; emergency shutdown is permanently unavailable [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5)

### Citations

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

**File:** x/cronos/keeper/msg_server.go (L84-87)
```go
// TurnBridge implements the grpc method
func (k msgServer) TurnBridge(goCtx context.Context, msg *types.MsgTurnBridge) (*types.MsgTurnBridgeResponse, error) {
	return nil, nil
}
```

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

**File:** docs/architecture/adr-009.md (L36-38)
```markdown
- Assign to each "restricted" messages in Cronos a permission (integer value) and create in Cronos module a mapping between addresses and permissions that is stored in memory. For now, there are only two messages that require permission : MsgUpdateTokenMapping and MsgTurnBridge.
- Create a msg type "MsgUpdatePermissions" that only admin can use and allow to update the address permission mapping.
- Change the logic to always check for the permission before processing the restricted messages.
```

**File:** proto/cronos/tx.proto (L81-89)
```text
// MsgTurnBridge defines the request type
message MsgTurnBridge {
  option (cosmos.msg.v1.signer) = "sender";
  string sender                 = 1;
  bool   enable                 = 2;
}

// MsgTurnBridgeResponse defines the response type
message MsgTurnBridgeResponse {}
```
