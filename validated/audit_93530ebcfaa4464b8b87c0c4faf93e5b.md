### Title
`MsgTurnBridge` Handler Is a No-Op Stub — Missing Permission Check and Missing Bridge State Change - (File: x/cronos/keeper/msg_server.go)

### Summary

The `TurnBridge` message handler in Cronos is an unimplemented stub that returns `nil, nil` unconditionally. It performs no permission check and makes no state change. Any unprivileged user can call `MsgTurnBridge` and receive a success response, bypassing the `CanTurnBridge` authorization check entirely. Simultaneously, the bridge circuit-breaker is permanently non-functional: no caller — including the admin or a permissioned address — can ever actually disable the bridge.

### Finding Description

The Cronos permission system defines a `CanTurnBridge` bit-flag permission and a `MsgTurnBridge` message specifically to allow the admin or a delegated address to disable the gravity bridge in an emergency (the circuit-breaker pattern described in ADR-009). [1](#0-0) 

The `UpdateTokenMapping` handler correctly enforces its analogous permission: [2](#0-1) 

However, the `TurnBridge` handler is a bare stub: [3](#0-2) 

It:
1. **Never calls `HasPermission` with `CanTurnBridge`** — the permission bit defined in `permissions.go` is never enforced on this code path.
2. **Never reads or writes any bridge-enable state** — the bridge cannot be turned off or on via this message.
3. **Returns `nil, nil`** — the Cosmos SDK interprets this as a successful transaction for any sender.

The proto definition confirms `MsgTurnBridge` is a live, registered RPC endpoint: [4](#0-3) 

### Impact Explanation

**Auth bypass (High):** Any unprivileged address can submit `MsgTurnBridge` and receive a success response (`code == 0`). The `CanTurnBridge` authorization check — which exists in the permission system and is expected by the integration test — is completely absent from the handler. This is a bypass of the bridge authorization check.

**Permanent inability to disable the bridge (High):** The gravity bridge circuit-breaker is permanently non-functional. In a bridge exploit or emergency, the admin or a permissioned operator cannot disable the bridge via `MsgTurnBridge`. The `CanTurnBridge` permission bit, the `UpdatePermissions` message, and the ADR-009 design are all rendered meaningless for this operation. [5](#0-4) 

### Likelihood Explanation

The entry path is a live, registered gRPC/Cosmos message endpoint reachable by any unprivileged user on the network. No special privileges, keys, or conditions are required to trigger the bypass. The only prerequisite is submitting a valid `MsgTurnBridge` transaction.

### Recommendation

Implement the `TurnBridge` handler with:
1. A `HasPermission` check against `CanTurnBridge` (mirroring `UpdateTokenMapping`).
2. Actual bridge enable/disable state logic (e.g., writing a bridge-enabled flag to the KV store and having the gravity hook respect it).

```go
func (k msgServer) TurnBridge(goCtx context.Context, msg *types.MsgTurnBridge) (*types.MsgTurnBridgeResponse, error) {
    ctx := sdk.UnwrapSDKContext(goCtx)
    signer, err := sdk.AccAddressFromBech32(msg.Sender)
    if err != nil {
        return nil, err
    }
    if !k.HasPermission(ctx, []sdk.AccAddress{signer}, CanTurnBridge) {
        return nil, errors.Wrap(sdkerrors.ErrUnauthorized, "msg sender is not authorized")
    }
    // write bridge-enabled state
    k.SetBridgeEnabled(ctx, msg.Enable)
    return &types.MsgTurnBridgeResponse{}, nil
}
```

### Proof of Concept

1. Any unprivileged address submits `MsgTurnBridge{Sender: attacker, Enable: false}`.
2. The handler executes `return nil, nil` — no permission check, no state change.
3. The transaction is included in a block with `code == 0` (success).
4. The bridge remains enabled; the circuit-breaker has no effect.
5. Simultaneously, the legitimate admin calling `TurnBridge` with `Enable: false` also has no effect — the bridge cannot be disabled. [3](#0-2) [6](#0-5)

### Citations

**File:** x/cronos/keeper/permissions.go (L13-17)
```go
const (
	CanChangeTokenMapping uint64                                  = 1 << iota // 1
	CanTurnBridge                                                             // 2
	All                   = CanChangeTokenMapping | CanTurnBridge             // 3
)
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

**File:** x/cronos/keeper/msg_server.go (L84-87)
```go
// TurnBridge implements the grpc method
func (k msgServer) TurnBridge(goCtx context.Context, msg *types.MsgTurnBridge) (*types.MsgTurnBridgeResponse, error) {
	return nil, nil
}
```

**File:** proto/cronos/tx.proto (L29-30)
```text
  // TurnBridge defines a method to disable or enable the gravity bridge
  rpc TurnBridge(MsgTurnBridge) returns (MsgTurnBridgeResponse);
```

**File:** docs/architecture/adr-009.md (L36-38)
```markdown
- Assign to each "restricted" messages in Cronos a permission (integer value) and create in Cronos module a mapping between addresses and permissions that is stored in memory. For now, there are only two messages that require permission : MsgUpdateTokenMapping and MsgTurnBridge.
- Create a msg type "MsgUpdatePermissions" that only admin can use and allow to update the address permission mapping.
- Change the logic to always check for the permission before processing the restricted messages.
```
