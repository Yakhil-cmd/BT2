### Title
`TurnBridge` Missing Permission Check and No-Op Stub Bypasses Bridge Authorization - (File: x/cronos/keeper/msg_server.go)

### Summary
The `TurnBridge` message handler is implemented as a bare stub returning `nil, nil` with no permission check and no state mutation. Any unprivileged user can submit `MsgTurnBridge` and receive a success response, fully bypassing the `CanTurnBridge` authorization guard. Simultaneously, the bridge circuit-breaker is permanently inoperative — even the legitimate admin cannot disable the gravity bridge in an emergency.

### Finding Description
The bug class from the external report is **auth bypass via a guard that always returns the permissive result**. In the external report the guard function `isTargetContractAllowed` always returns `true` due to a flawed assembly check. The Cronos analog is structurally identical: the `TurnBridge` handler unconditionally returns the permissive result (`nil, nil` = success) for every caller, because the entire body is a stub with no permission check and no implementation.

`UpdateTokenMapping` — the sibling handler for the other privileged bridge operation — correctly enforces authorization:

```go
// x/cronos/keeper/msg_server.go:69-81
func (k msgServer) UpdateTokenMapping(...) (...) {
    ctx := sdk.UnwrapSDKContext(goCtx)
    if !k.HasPermission(ctx, msg.GetSigners(), CanChangeTokenMapping) {
        return nil, errors.Wrap(sdkerrors.ErrUnauthorized, "msg sender is not authorized")
    }
    ...
}
``` [1](#0-0) 

`TurnBridge`, by contrast, is:

```go
// x/cronos/keeper/msg_server.go:84-87
func (k msgServer) TurnBridge(goCtx context.Context, msg *types.MsgTurnBridge) (*types.MsgTurnBridgeResponse, error) {
    return nil, nil
}
``` [2](#0-1) 

The `CanTurnBridge` permission constant is defined and is part of the permission system: [3](#0-2) 

`HasPermission` is the correct enforcement primitive and is used for `UpdateTokenMapping` but is never called inside `TurnBridge`: [4](#0-3) 

The `MsgTurnBridge` message is a fully registered, publicly reachable gRPC endpoint: [5](#0-4) 

The proto definition confirms `sender` is the signer field, so any valid bech32 address can submit it: [6](#0-5) 

### Impact Explanation
Two distinct impacts arise from the same stub:

1. **Auth bypass (High):** Any unprivileged user can submit `MsgTurnBridge` and receive a `code=0` success response, bypassing the `CanTurnBridge` authorization check entirely. The integration test itself documents the expected behavior — non-admin callers must be rejected — but the implementation never enforces it: [7](#0-6) 

2. **Permanent inability to operate the bridge circuit-breaker (High):** Because the stub does nothing, even the legitimate admin cannot disable the gravity bridge in an emergency. The `TurnBridge` message is the sole mechanism for the emergency circuit-breaker described in ADR-009:

This means the bridge-halt capability is permanently broken for all parties, matching the "Permanent or long-lived inability for honest users or validators to process valid transactions, bridge/conversion flows" impact class.

### Likelihood Explanation
The entry path is fully unprivileged and requires only a valid bech32 sender address, which `ValidateBasic` already enforces: [8](#0-7) 

Any on-chain account can submit the transaction. No special setup, leaked keys, or governance compromise is required.

### Recommendation
Implement `TurnBridge` with the same pattern used by `UpdateTokenMapping`:

```go
func (k msgServer) TurnBridge(goCtx context.Context, msg *types.MsgTurnBridge) (*types.MsgTurnBridgeResponse, error) {
    ctx := sdk.UnwrapSDKContext(goCtx)
    signers := []sdk.AccAddress{sdk.MustAccAddressFromBech32(msg.Sender)}
    if !k.HasPermission(ctx, signers, CanTurnBridge) {
        return nil, errors.Wrap(sdkerrors.ErrUnauthorized, "msg sender is not authorized")
    }
    // update bridge-enabled param or gravity bridge state
    ...
    return &types.MsgTurnBridgeResponse{}, nil
}
```

### Proof of Concept
1. Any account submits `MsgTurnBridge{Sender: <any_valid_address>, Enable: false}`.
2. The handler executes `return nil, nil` — no permission check, no state change.
3. The transaction is accepted on-chain with `code=0`.
4. The bridge state is unchanged (circuit-breaker is inoperative).
5. The integration test assertion `assert rsp["code"] != 0, "should not have the permission"` would fail against the live implementation for any non-admin caller. [2](#0-1)

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

**File:** x/cronos/types/tx.pb.go (L986-1002)
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
}
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

**File:** integration_tests/test_gravity.py (L660-665)
```python
    # turn off bridge
    rsp = cli.turn_bridge("false", from_="community")
    assert rsp["code"] != 0, "should not have the permission"

    rsp = cli.turn_bridge("false", from_="validator")
    assert rsp["code"] == 0, rsp["raw_log"]
```

**File:** x/cronos/types/messages.go (L133-141)
```go
// ValidateBasic ...
func (msg *MsgTurnBridge) ValidateBasic() error {
	_, err := sdk.AccAddressFromBech32(msg.Sender)
	if err != nil {
		return errors.Wrapf(sdkerrors.ErrInvalidAddress, "invalid sender address (%s)", err)
	}

	return nil
}
```
