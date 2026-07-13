### Title
`MsgTurnBridge` Handler Is a No-Op Stub: Bridge Circuit Breaker Permanently Broken and `CanTurnBridge` Permission Check Bypassed - (File: x/cronos/keeper/msg_server.go)

### Summary
The `TurnBridge` message handler in `x/cronos/keeper/msg_server.go` is implemented as a bare no-op stub (`return nil, nil`). It performs no permission check and makes no state change. Any unprivileged user can submit `MsgTurnBridge` and receive a success response, bypassing the `CanTurnBridge` permission system entirely. Simultaneously, authorized admins holding `CanTurnBridge` permission cannot actually disable the bridge in an emergency because the handler does nothing.

### Finding Description
The Cronos module defines a bridge circuit breaker via `MsgTurnBridge` (defined in `proto/cronos/tx.proto`), backed by the `CanTurnBridge` permission bit in `x/cronos/keeper/permissions.go`. ADR-009 explicitly documents the design intent: only addresses with `CanTurnBridge` permission (or the `CronosAdmin`) may enable or disable the bridge as an emergency circuit breaker.

The `CanTurnBridge` permission constant is defined:

```go
const (
    CanChangeTokenMapping uint64 = 1 << iota // 1
    CanTurnBridge                             // 2
    All = CanChangeTokenMapping | CanTurnBridge // 3
)
```

The `HasPermission` enforcement function exists and is used by `UpdateTokenMapping`. However, the actual `TurnBridge` handler implementation is:

```go
// TurnBridge implements the grpc method
func (k msgServer) TurnBridge(goCtx context.Context, msg *types.MsgTurnBridge) (*types.MsgTurnBridgeResponse, error) {
    return nil, nil
}
```

This stub:
1. Performs **no** `HasPermission(ctx, [sender], CanTurnBridge)` check
2. Makes **no** state change (does not update any bridge-active parameter)
3. Returns success (`nil, nil`) for **any** caller

Compare with `UpdateTokenMapping`, which correctly calls `HasPermission`, and `UpdateParams`, which checks `msg.Authority != k.authority`. `TurnBridge` has neither guard.

The gRPC handler is fully registered and reachable via the `_Msg_TurnBridge_Handler` dispatch in `tx.pb.go`, and the CLI command `CmdTurnBridge` in `x/cronos/client/cli/tx.go` exposes it to any user.

### Impact Explanation
**High — Bypass of Cronos permission/bridge authorization checks:**
Any unprivileged user can submit `MsgTurnBridge{Sender: <any_address>, Enable: false}` and receive a `200 OK` success response. The `CanTurnBridge` permission system is completely bypassed at the handler level. The permission bit is defined, the `HasPermission` function exists, but it is never called in this handler.

**High — Permanent inability for authorized admins to use the bridge circuit breaker:**
Because the handler is a no-op, even an address that legitimately holds `CanTurnBridge` permission cannot disable the bridge. In the event of a live bridge exploit (e.g., analogous to the `SendCroToIbc` drain vulnerability addressed in the upgrade handler via `CroBridgeContractAddresses`), the intended fast circuit breaker path is permanently non-functional. The only remaining path to disable the bridge would be a full governance `MsgUpdateParams` proposal, which takes governance voting time and cannot serve as an emergency stop.

### Likelihood Explanation
The `TurnBridge` gRPC endpoint is registered, reachable by any user, and the CLI exposes it. The no-op stub is the current production implementation. The integration test `test_gravity_turn_bridge` in `integration_tests/test_gravity.py` demonstrates the expected behavior (turning the bridge off should block `send_to_evm_chain`), but that test exercises the gravity bridge path which is separate from this handler. The handler stub means the circuit breaker has never worked.

### Recommendation
Implement the `TurnBridge` handler with a `HasPermission` check and an actual state change:

```go
func (k msgServer) TurnBridge(goCtx context.Context, msg *types.MsgTurnBridge) (*types.MsgTurnBridgeResponse, error) {
    ctx := sdk.UnwrapSDKContext(goCtx)
    sender, err := sdk.AccAddressFromBech32(msg.Sender)
    if err != nil {
        return nil, err
    }
    if !k.HasPermission(ctx, []sdk.AccAddress{sender}, CanTurnBridge) {
        return nil, errors.Wrap(sdkerrors.ErrUnauthorized, "msg sender is not authorized")
    }
    params := k.GetParams(ctx)
    // set the appropriate bridge-active field
    params.EnableAutoDeployment = msg.Enable
    if err := k.SetParams(ctx, params); err != nil {
        return nil, err
    }
    return &types.MsgTurnBridgeResponse{}, nil
}
```

### Proof of Concept
1. Any user constructs `MsgTurnBridge{Sender: "<unprivileged_address>", Enable: false}` and broadcasts it.
2. The handler at `x/cronos/keeper/msg_server.go:85-87` executes `return nil, nil` — no permission check, no state change.
3. The transaction is accepted on-chain with a success code.
4. The bridge state is unchanged; `CanTurnBridge`-permissioned admins also cannot disable the bridge via this path.
5. In an emergency requiring the bridge circuit breaker, the only recourse is a slow governance `MsgUpdateParams` proposal, defeating the purpose of the permissioned fast-path circuit breaker. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4)

### Citations

**File:** x/cronos/keeper/msg_server.go (L84-87)
```go
// TurnBridge implements the grpc method
func (k msgServer) TurnBridge(goCtx context.Context, msg *types.MsgTurnBridge) (*types.MsgTurnBridgeResponse, error) {
	return nil, nil
}
```

**File:** x/cronos/keeper/permissions.go (L13-16)
```go
const (
	CanChangeTokenMapping uint64                                  = 1 << iota // 1
	CanTurnBridge                                                             // 2
	All                   = CanChangeTokenMapping | CanTurnBridge             // 3
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
