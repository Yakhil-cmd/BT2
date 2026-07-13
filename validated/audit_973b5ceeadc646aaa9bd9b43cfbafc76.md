### Title
`TurnBridge` Missing Permission Check and No-Op Implementation Allows Unprivileged Bypass of Bridge Authorization - (File: x/cronos/keeper/msg_server.go)

### Summary

The `TurnBridge` message handler is implemented as a bare no-op that returns `nil, nil` with no permission check and no state mutation. Any unprivileged user can submit `MsgTurnBridge` and receive a success response, bypassing the `CanTurnBridge` authorization guard entirely. Simultaneously, the gravity bridge circuit breaker is permanently non-functional: even authorized users cannot actually disable the bridge.

### Finding Description

`x/cronos/keeper/msg_server.go` lines 84–87:

```go
// TurnBridge implements the grpc method
func (k msgServer) TurnBridge(goCtx context.Context, msg *types.MsgTurnBridge) (*types.MsgTurnBridgeResponse, error) {
    return nil, nil
}
``` [1](#0-0) 

Compare to `UpdateTokenMapping`, the sibling restricted message, which correctly gates on `HasPermission`:

```go
func (k msgServer) UpdateTokenMapping(...) (*MsgUpdateTokenMappingResponse, error) {
    ctx := sdk.UnwrapSDKContext(goCtx)
    if !k.HasPermission(ctx, msg.GetSigners(), CanChangeTokenMapping) {
        return nil, errors.Wrap(sdkerrors.ErrUnauthorized, "msg sender is not authorized")
    }
    ...
}
``` [2](#0-1) 

The permission system defines `CanTurnBridge` as a distinct bit that must be held by the caller or the caller must be the `CronosAdmin`: [3](#0-2) 

`HasPermission` enforces this for every other restricted message: [4](#0-3) 

`TurnBridge` calls none of this. It performs zero permission checks and zero state writes.

The integration test `test_gravity_turn_bridge` explicitly expects that a non-admin caller receives `code != 0` and that after a successful admin call the bridge is actually disabled: [5](#0-4) 

Both expectations are violated by the current implementation.

### Impact Explanation

**High – Bypass of Cronos bridge authorization check:** Any unprivileged address can submit `MsgTurnBridge` and the chain accepts it with a success response (`code == 0`). The `CanTurnBridge` permission bit and the `CronosAdmin` guard are completely bypassed. This directly matches the allowed High impact: *"Bypass of Cronos admin, governance authority, permission … bridge … authorization checks."*

**High – Permanent inability to disable the bridge:** Because the function is a no-op, no actor — including the admin — can ever disable the gravity bridge. The emergency circuit breaker described in ADR-009 is permanently broken. This matches: *"Permanent or long-lived inability for honest users or validators to process valid … bridge/conversion flows … under normal network assumptions."*

### Likelihood Explanation

The entry path is fully reachable by any unprivileged user. `MsgTurnBridge` is a registered gRPC message: [6](#0-5) 

No special privileges, leaked keys, or cryptographic breaks are required. A standard signed transaction suffices.

### Recommendation

Implement `TurnBridge` with the same pattern as `UpdateTokenMapping`:

```go
func (k msgServer) TurnBridge(goCtx context.Context, msg *types.MsgTurnBridge) (*types.MsgTurnBridgeResponse, error) {
    ctx := sdk.UnwrapSDKContext(goCtx)
    if !k.HasPermission(ctx, msg.GetSigners(), CanTurnBridge) {
        return nil, errors.Wrap(sdkerrors.ErrUnauthorized, "msg sender is not authorized")
    }
    params := k.GetParams(ctx)
    params.EnableGravity = msg.Enable
    if err := k.SetParams(ctx, params); err != nil {
        return nil, err
    }
    return &types.MsgTurnBridgeResponse{}, nil
}
```

### Proof of Concept

1. Any address (no `CanTurnBridge` permission, not `CronosAdmin`) submits:
   ```
   MsgTurnBridge { Sender: "unprivileged_address", Enable: false }
   ```
2. The chain processes the transaction and returns `code == 0` (success).
3. The bridge state is unchanged — the gravity bridge remains enabled.
4. Even the admin submitting the same message cannot disable the bridge, because the function never writes any state.
5. The integration test at `integration_tests/test_gravity.py:661` (`assert rsp["code"] != 0, "should not have the permission"`) would pass for the wrong reason (the function succeeds for everyone), and the subsequent bridge-disabled assertions would fail. [1](#0-0)

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

**File:** integration_tests/test_gravity.py (L661-681)
```python
    rsp = cli.turn_bridge("false", from_="community")
    assert rsp["code"] != 0, "should not have the permission"

    rsp = cli.turn_bridge("false", from_="validator")
    assert rsp["code"] == 0, rsp["raw_log"]
    wait_for_new_blocks(cli, 1)

    if gravity.cronos.enable_auto_deployment:
        # send it back to erc20, should fail
        tx = crc21_contract.functions.send_to_evm_chain(
            ADDRS["validator"], amount, 1, 0, b""
        ).build_transaction({"from": ADDRS["community"]})
        txreceipt = send_transaction(cronos_w3, tx, KEYS["community"])
        assert txreceipt.status == 0, "should fail"
    else:
        # send back the gravity native tokens, should fail
        rsp = cli.send_to_ethereum(
            ADDRS["validator"], f"{amount}{denom}", f"0{denom}", from_="community"
        )
        assert rsp["code"] == 3, rsp["raw_log"]

```

**File:** proto/cronos/tx.proto (L29-30)
```text
  // TurnBridge defines a method to disable or enable the gravity bridge
  rpc TurnBridge(MsgTurnBridge) returns (MsgTurnBridgeResponse);
```
