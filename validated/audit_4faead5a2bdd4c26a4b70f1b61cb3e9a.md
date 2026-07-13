### Title
Missing Authorization Check and No-Op Implementation in `MsgTurnBridge` Handler — (File: `x/cronos/keeper/msg_server.go`)

### Summary

The `TurnBridge` message handler in `x/cronos/keeper/msg_server.go` is implemented as a bare `return nil, nil` stub. It performs no authorization check and makes no state change. Any unprivileged user can submit `MsgTurnBridge` and receive a success response (code 0), bypassing the `CanTurnBridge` permission that the permission system explicitly defines for this message. Simultaneously, the bridge circuit-breaker is permanently non-functional: even the admin cannot stop the gravity bridge in an emergency.

### Finding Description

ADR-009 explicitly lists `MsgTurnBridge` as one of the two messages that must be gated by the `CanTurnBridge` permission bit. The companion message `MsgUpdateTokenMapping` is correctly guarded:

```go
// UpdateTokenMapping implements the grpc method
func (k msgServer) UpdateTokenMapping(...) (...) {
    if !k.HasPermission(ctx, msg.GetSigners(), CanChangeTokenMapping) {
        return nil, errors.Wrap(sdkerrors.ErrUnauthorized, "msg sender is not authorized")
    }
    ...
}
``` [1](#0-0) 

The `TurnBridge` handler, however, is:

```go
// TurnBridge implements the grpc method
func (k msgServer) TurnBridge(goCtx context.Context, msg *types.MsgTurnBridge) (*types.MsgTurnBridgeResponse, error) {
    return nil, nil
}
``` [2](#0-1) 

The `CanTurnBridge` constant is defined and the `HasPermission` helper exists, but is never called for this message: [3](#0-2) 

The proto definition confirms `MsgTurnBridge` is a live, registered RPC endpoint: [4](#0-3) 

The gRPC service descriptor wires it to the live handler: [5](#0-4) 

### Impact Explanation

Two distinct impacts arise from the same root cause:

1. **Authorization bypass (High):** Any unprivileged address can broadcast `MsgTurnBridge` and receive a success response (`code = 0`). The `CanTurnBridge` permission check — which ADR-009 mandates — is entirely absent. This directly matches the allowed High impact: *"Bypass of Cronos admin, governance authority, permission, token-mapping, bridge, block-list, or module-account authorization checks."*

2. **Permanent inability to stop the bridge (High):** Because the handler is a no-op, even the admin or a permissioned address cannot disable the gravity bridge in an emergency. The circuit-breaker that ADR-009 was designed to provide is permanently broken. This matches: *"Permanent or long-lived inability for honest users or validators to process valid transactions, bridge/conversion flows."* [6](#0-5) 

### Likelihood Explanation

The entry path is fully open: `MsgTurnBridge` is a registered Cosmos SDK message, callable by any address with a funded account and gas. No special role, key, or network position is required. The attacker only needs to broadcast a standard signed transaction.

### Recommendation

Implement `TurnBridge` with the same pattern used by `UpdateTokenMapping`:

1. Add a `HasPermission(ctx, msg.GetSigners(), CanTurnBridge)` guard at the top of the handler.
2. Implement the actual bridge-state mutation (set the bridge-enabled flag in params or a dedicated store key).
3. Add a unit test mirroring the existing `TestHasPermissions` pattern to assert that an unpermissioned sender is rejected. [2](#0-1) 

### Proof of Concept

1. Start a local Cronos node with the gravity bridge enabled.
2. Generate any funded address `ATTACKER` that has no `CanTurnBridge` permission (default state for all addresses).
3. Broadcast:
   ```
   cronosd tx cronos turn-bridge false --from ATTACKER --chain-id cronos_777-1 -y
   ```
4. Observe `code: 0` in the response — the transaction is accepted with no authorization error.
5. Query bridge state: the bridge is still enabled (no state change occurred), confirming the no-op.
6. Repeat with the admin address: same `code: 0`, same no-op — confirming the circuit-breaker is non-functional for all callers including the admin.

The integration test `test_gravity_turn_bridge` already asserts `rsp["code"] != 0` for a non-admin caller, but this assertion would fail against the current implementation because the handler returns `nil` unconditionally. [2](#0-1) [7](#0-6)

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

**File:** proto/cronos/tx.proto (L29-30)
```text
  // TurnBridge defines a method to disable or enable the gravity bridge
  rpc TurnBridge(MsgTurnBridge) returns (MsgTurnBridgeResponse);
```

**File:** x/cronos/types/tx.pb.go (L986-1001)
```go
func _Msg_TurnBridge_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(MsgTurnBridge)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(MsgServer).TurnBridge(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/cronos.Msg/TurnBridge",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(MsgServer).TurnBridge(ctx, req.(*MsgTurnBridge))
	}
	return interceptor(ctx, in, info, handler)
```

**File:** docs/architecture/adr-009.md (L36-38)
```markdown
- Assign to each "restricted" messages in Cronos a permission (integer value) and create in Cronos module a mapping between addresses and permissions that is stored in memory. For now, there are only two messages that require permission : MsgUpdateTokenMapping and MsgTurnBridge.
- Create a msg type "MsgUpdatePermissions" that only admin can use and allow to update the address permission mapping.
- Change the logic to always check for the permission before processing the restricted messages.
```
