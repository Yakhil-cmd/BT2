### Title
Missing Access Control and Unimplemented `TurnBridge` Handler Permanently Disables Bridge Circuit Breaker - (File: x/cronos/keeper/msg_server.go)

### Summary
The `TurnBridge` message handler in `x/cronos/keeper/msg_server.go` is a stub that unconditionally returns `nil, nil`. It performs no `CanTurnBridge` permission check and modifies no bridge state. Any unprivileged address can submit `MsgTurnBridge` and receive a success response, while the bridge circuit breaker is permanently non-functional — the bridge can never be disabled, even in an emergency.

### Finding Description
ADR-009 explicitly designates `MsgTurnBridge` as a restricted, permissioned operation requiring the `CanTurnBridge` bit, alongside `MsgUpdateTokenMapping`. The permission system is correctly implemented for `UpdateTokenMapping`:

```go
// x/cronos/keeper/msg_server.go:69-82
func (k msgServer) UpdateTokenMapping(...) {
    if !k.HasPermission(ctx, msg.GetSigners(), CanChangeTokenMapping) {
        return nil, errors.Wrap(sdkerrors.ErrUnauthorized, "msg sender is not authorized")
    }
    ...
}
``` [1](#0-0) 

But `TurnBridge` is a stub:

```go
// x/cronos/keeper/msg_server.go:84-87
func (k msgServer) TurnBridge(goCtx context.Context, msg *types.MsgTurnBridge) (*types.MsgTurnBridgeResponse, error) {
    return nil, nil
}
``` [2](#0-1) 

Two distinct defects are present simultaneously:
1. **Missing auth guard**: No call to `HasPermission(ctx, ..., CanTurnBridge)` — any unprivileged sender passes.
2. **Missing implementation**: No bridge state is read or written; the handler is a no-op.

The permission constants confirm `CanTurnBridge` was intended to gate this path: [3](#0-2) 

And ADR-009 confirms the design intent: [4](#0-3) 

### Impact Explanation
**High — Permanent inability to halt bridge/conversion flows.**

The `TurnBridge` message is the sole on-chain circuit breaker for the Gravity bridge. Because the handler is a no-op, the bridge state can never be set to disabled by any actor — admin, permissioned address, or governance. In a live bridge exploit or oracle manipulation event, the intended emergency stop is unreachable. This satisfies:

> *High: Permanent or long-lived inability for honest users or validators to process valid transactions, bridge/conversion flows … under normal network assumptions.*

Additionally, the missing permission guard satisfies:

> *High: Bypass of Cronos admin, governance authority, permission … authorization checks.*

Any unprivileged address submitting `MsgTurnBridge` receives a success response, silently bypassing the `CanTurnBridge` RBAC layer.

### Likelihood Explanation
The handler is reachable via the standard Cosmos SDK transaction path — any address can broadcast a `MsgTurnBridge` transaction. No special privilege, leaked key, or cryptographic break is required. The stub is present in the production keeper, not in tests or mocks.

### Recommendation
Implement `TurnBridge` with:
1. A `HasPermission(ctx, msg.GetSigners(), CanTurnBridge)` guard mirroring `UpdateTokenMapping`.
2. Actual bridge-enabled state persistence (read/write the bridge-enabled flag in the KV store).
3. Emit an appropriate event on state change.

### Proof of Concept
1. Attacker (any unprivileged address) broadcasts `MsgTurnBridge{enable: false}`.
2. `TurnBridge` is invoked; no permission check is executed.
3. Handler returns `(nil, nil)` — the transaction is accepted on-chain as successful.
4. No bridge state is modified; the bridge remains permanently active.
5. Legitimate admin later attempts to halt the bridge during an exploit — the same no-op executes, the bridge cannot be stopped, and funds continue to flow through a compromised bridge. [2](#0-1)

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

**File:** docs/architecture/adr-009.md (L36-38)
```markdown
- Assign to each "restricted" messages in Cronos a permission (integer value) and create in Cronos module a mapping between addresses and permissions that is stored in memory. For now, there are only two messages that require permission : MsgUpdateTokenMapping and MsgTurnBridge.
- Create a msg type "MsgUpdatePermissions" that only admin can use and allow to update the address permission mapping.
- Change the logic to always check for the permission before processing the restricted messages.
```
