### Title
`TurnBridge` Message Handler Is a No-Op — Bridge State Can Never Be Toggled - (File: `x/cronos/keeper/msg_server.go`)

### Summary

The `MsgTurnBridge` message is fully defined in the proto surface and a `CanTurnBridge` permission bit is reserved in the permissions system, but the `TurnBridge` handler in `msg_server.go` is an unimplemented stub that unconditionally returns `nil, nil` without performing any state change. As a result, the bridge can never be disabled or re-enabled through the intended administrative path, and the `CanTurnBridge` permission is permanently inert.

### Finding Description

`proto/cronos/tx.proto` declares `MsgTurnBridge` with a `sender` and `enable bool` field, and registers it as an RPC on the `Msg` service:

```proto
rpc TurnBridge(MsgTurnBridge) returns (MsgTurnBridgeResponse);
```

`x/cronos/keeper/permissions.go` reserves a dedicated permission bit for this operation:

```go
const (
    CanChangeTokenMapping uint64 = 1 << iota // 1
    CanTurnBridge                             // 2
    All = CanChangeTokenMapping | CanTurnBridge // 3
)
```

The `CronosAdmin` can grant `CanTurnBridge` to any address via `UpdatePermissions`. However, the actual handler in `msg_server.go` is:

```go
// TurnBridge implements the grpc method
func (k msgServer) TurnBridge(goCtx context.Context, msg *types.MsgTurnBridge) (*types.MsgTurnBridgeResponse, error) {
    return nil, nil
}
```

It performs no permission check, reads no state, writes no state, and returns success unconditionally. The bridge enable/disable state is never read or written anywhere in the keeper. This is the direct Cronos analog of H-03: a privileged administrative function (`TurnBridge`) is exposed on the message surface and has a dedicated permission (`CanTurnBridge`), but the underlying implementation is missing, making the control permanently non-functional.

### Impact Explanation

The Gravity Bridge and IBC bridge flows are always active with no on-chain kill switch. If a critical vulnerability is discovered in the bridge (e.g., unauthorized minting via a malicious EVM log, double-spend in the IBC voucher conversion path, or a Gravity Bridge relay exploit), the `CronosAdmin` and any address holding `CanTurnBridge` permission have no ability to halt bridge operations. The `CanTurnBridge` permission bit is permanently inert. This constitutes a **permanent inability for the admin to halt bridge/conversion flows**, which maps directly to the High impact category: *"Permanent or long-lived inability for honest users or validators to process valid transactions, bridge/conversion flows, precompile calls, IBC transfers, or block proposals under normal network assumptions"* and *"High: Bypass of Cronos admin, governance authority, permission, token-mapping, bridge, block-list, or module-account authorization checks."*

### Likelihood Explanation

The `MsgTurnBridge` message is reachable by any address — the handler accepts the transaction and returns success without error. The `CronosAdmin` can grant `CanTurnBridge` to an operator address. Both parties would reasonably believe the bridge has been toggled when in fact nothing changed. The stub is silently broken: no error is returned, no event is emitted, and no state is written. Discovery of this gap requires reading the source; it is not surfaced at runtime.

### Recommendation

Implement the `TurnBridge` handler to:
1. Verify the caller holds `CanTurnBridge` permission (via `k.HasPermission`).
2. Read the `enable` field from `msg`.
3. Persist the bridge-enabled flag to a dedicated key in the module's KV store (or as a field in `Params`).
4. Have all bridge-triggering paths (EVM hooks in `send_to_ibc.go`, `send_cro_to_ibc.go`, etc.) gate on this flag and return an error when the bridge is disabled.
5. Emit an event recording the state change and the caller.

### Proof of Concept

1. `CronosAdmin` calls `MsgUpdatePermissions` granting `CanTurnBridge` (bit `2`) to address `A`.
2. Address `A` submits `MsgTurnBridge{sender: A, enable: false}`.
3. The handler at `x/cronos/keeper/msg_server.go:85-87` returns `nil, nil` — the transaction succeeds with no state change.
4. Bridge EVM hooks (`send_to_ibc.go`, `send_cro_to_ibc.go`) continue to execute normally.
5. The bridge is never disabled; the admin has no on-chain mechanism to halt it. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3)

### Citations

**File:** x/cronos/keeper/msg_server.go (L84-87)
```go
// TurnBridge implements the grpc method
func (k msgServer) TurnBridge(goCtx context.Context, msg *types.MsgTurnBridge) (*types.MsgTurnBridgeResponse, error) {
	return nil, nil
}
```

**File:** x/cronos/keeper/msg_server.go (L102-116)
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

**File:** proto/cronos/tx.proto (L29-30)
```text
  // TurnBridge defines a method to disable or enable the gravity bridge
  rpc TurnBridge(MsgTurnBridge) returns (MsgTurnBridgeResponse);
```
