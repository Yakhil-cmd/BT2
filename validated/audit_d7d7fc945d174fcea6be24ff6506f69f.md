### Title
`MsgTurnBridge` Handler Is a No-Op Stub with No Access Control — Any Caller Succeeds, Bridge Circuit Breaker Is Permanently Broken - (File: `x/cronos/keeper/msg_server.go`)

### Summary

The `TurnBridge` message handler in `x/cronos/keeper/msg_server.go` is an unimplemented stub that returns `nil, nil` unconditionally. It performs no permission check and no state change. Any unprivileged user can call `MsgTurnBridge` and receive a success response, while the intended `CanTurnBridge` permission gate is completely bypassed. Simultaneously, the bridge circuit breaker is permanently non-functional: even the admin cannot disable the bridge.

### Finding Description

The Cronos permission system (ADR-009) defines `CanTurnBridge` as a privileged bit-flag permission. `UpdateTokenMapping` correctly enforces this pattern:

```go
// UpdateTokenMapping implements the grpc method
func (k msgServer) UpdateTokenMapping(...) (...) {
    if !k.HasPermission(ctx, msg.GetSigners(), CanChangeTokenMapping) {
        return nil, errors.Wrap(sdkerrors.ErrUnauthorized, "msg sender is not authorized")
    }
    ...
}
``` [1](#0-0) 

`TurnBridge`, which is supposed to be the emergency circuit breaker for the gravity bridge and is equally privileged, has this implementation:

```go
// TurnBridge implements the grpc method
func (k msgServer) TurnBridge(goCtx context.Context, msg *types.MsgTurnBridge) (*types.MsgTurnBridgeResponse, error) {
    return nil, nil
}
``` [2](#0-1) 

There is no call to `HasPermission`, no state write, and no error returned. The `CanTurnBridge` permission constant is defined and the permission system is wired up, but the handler never consults it. [3](#0-2) 

The message is fully registered in the gRPC service and reachable by any on-chain sender: [4](#0-3) [5](#0-4) 

### Impact Explanation

Two distinct impacts arise from the same root cause:

1. **Auth bypass (High):** Any unprivileged address can submit `MsgTurnBridge` and receive a `code: 0` success response. The `CanTurnBridge` permission gate — which ADR-009 explicitly requires — is never evaluated. This is a direct bypass of the bridge authorization check. [6](#0-5) 

2. **Permanent bridge circuit-breaker failure (High):** Because the handler is a no-op, the bridge can never be disabled. In an emergency (e.g., a bridge exploit draining funds), the admin or governance cannot invoke the circuit breaker. The integration test confirms the intent — `turn_bridge("false", from_="validator")` is expected to succeed and halt bridge processing — but the on-chain handler silently discards the call. [7](#0-6) 

### Likelihood Explanation

The entry path is a standard signed Cosmos SDK transaction (`MsgTurnBridge`) with no preconditions. Any funded address can submit it. The stub has been present since the handler was scaffolded and will remain exploitable until the implementation is completed.

### Recommendation

Implement `TurnBridge` with the same permission pattern used by `UpdateTokenMapping`:

```go
func (k msgServer) TurnBridge(goCtx context.Context, msg *types.MsgTurnBridge) (*types.MsgTurnBridgeResponse, error) {
    ctx := sdk.UnwrapSDKContext(goCtx)
    if !k.HasPermission(ctx, msg.GetSigners(), CanTurnBridge) {
        return nil, errors.Wrap(sdkerrors.ErrUnauthorized, "msg sender is not authorized")
    }
    // persist bridge enabled/disabled state and enforce it in the gravity hook
    ...
    return &types.MsgTurnBridgeResponse{}, nil
}
```

The bridge-enabled flag must also be read and enforced in the gravity bridge ABCI/hook path so that disabling the bridge has actual effect.

### Proof of Concept

1. Any address (e.g., `community`) submits `MsgTurnBridge{sender: community, enable: false}`.
2. The handler at `msg_server.go:85-86` returns `nil, nil` — the transaction succeeds on-chain with `code: 0`.
3. No permission check is performed; `CanTurnBridge` is never consulted.
4. No bridge state is written; the bridge continues operating as if the call never happened.
5. The admin subsequently submits the same message intending to disable the bridge in an emergency — it also silently succeeds and does nothing, leaving the bridge permanently enabled.

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

**File:** x/cronos/keeper/permissions.go (L31-48)
```go
// HasPermission check if an account has a specific permission. by default cronos admin has all permissions
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

**File:** integration_tests/test_gravity.py (L661-665)
```python
    rsp = cli.turn_bridge("false", from_="community")
    assert rsp["code"] != 0, "should not have the permission"

    rsp = cli.turn_bridge("false", from_="validator")
    assert rsp["code"] == 0, rsp["raw_log"]
```
