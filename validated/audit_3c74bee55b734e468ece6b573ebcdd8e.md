### Title
`MsgTurnBridge` Handler Is a No-Op Stub — Missing Permission Check and State Update - (File: `x/cronos/keeper/msg_server.go`)

### Summary
The `TurnBridge` gRPC handler in `x/cronos/keeper/msg_server.go` is implemented as a complete stub that returns `nil, nil` unconditionally. It performs no permission check and makes no state change. Any unprivileged address can call `MsgTurnBridge` and receive a success response, while the bridge-active state is never actually modified. This simultaneously bypasses the `CanTurnBridge` authorization guard and permanently disables the bridge circuit-breaker.

### Finding Description
The `TurnBridge` message handler is defined as:

```go
// TurnBridge implements the grpc method
func (k msgServer) TurnBridge(goCtx context.Context, msg *types.MsgTurnBridge) (*types.MsgTurnBridgeResponse, error) {
    return nil, nil
}
``` [1](#0-0) 

Compare this to `UpdateTokenMapping`, which correctly gates execution behind `HasPermission`:

```go
if !k.HasPermission(ctx, msg.GetSigners(), CanChangeTokenMapping) {
    return nil, errors.Wrap(sdkerrors.ErrUnauthorized, "msg sender is not authorized")
}
``` [2](#0-1) 

The permission system explicitly defines `CanTurnBridge` as a distinct, required permission bit: [3](#0-2) 

The `MsgTurnBridge` message is a registered, live gRPC endpoint: [4](#0-3) 

### Impact Explanation
Two distinct impacts result from the stub:

1. **Auth bypass (High):** Any unprivileged address can submit `MsgTurnBridge` and receive a `code: 0` success response. The `CanTurnBridge` permission check — which is the entire purpose of the permission system described in ADR-009 — is never evaluated. [5](#0-4) 

2. **Permanent bridge circuit-breaker failure (High):** Because the handler never calls any keeper method to update `bridge_active`, the Gravity Bridge emergency stop mechanism is permanently non-functional. No actor — including the admin — can turn the bridge off via `MsgTurnBridge`. This matches the allowed impact: *"High: Permanent or long-lived inability for honest users or validators to process valid transactions, bridge/conversion flows."*

### Likelihood Explanation
The endpoint is reachable by any unprivileged user via a standard Cosmos SDK transaction. No special keys, roles, or conditions are required. The integration test `test_gravity_turn_bridge` explicitly expects `from_="community"` (unprivileged) to be rejected with a non-zero code, but the current implementation returns success for all callers. [6](#0-5) 

### Recommendation
Implement `TurnBridge` analogously to `UpdateTokenMapping`:
1. Check `HasPermission(ctx, msg.GetSigners(), CanTurnBridge)` and return `ErrUnauthorized` on failure.
2. Call the appropriate keeper method to update the `bridge_active` parameter in module state.

### Proof of Concept
1. Any address submits `MsgTurnBridge{Sender: <unprivileged_addr>, Enable: false}`.
2. The handler executes `return nil, nil` — no permission check, no state write.
3. The transaction is committed with `code: 0`.
4. `bridge_active` remains unchanged; the bridge cannot be disabled.
5. Repeat with `Enable: true` — same result. The bridge state is permanently frozen at its genesis value regardless of any `MsgTurnBridge` calls. [1](#0-0) [3](#0-2)

### Citations

**File:** x/cronos/keeper/msg_server.go (L72-75)
```go
	// check permission
	if !k.HasPermission(ctx, msg.GetSigners(), CanChangeTokenMapping) {
		return nil, errors.Wrap(sdkerrors.ErrUnauthorized, "msg sender is not authorized")
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

**File:** x/cronos/types/tx.pb.go (L1074-1077)
```go
		{
			MethodName: "TurnBridge",
			Handler:    _Msg_TurnBridge_Handler,
		},
```

**File:** docs/architecture/adr-009.md (L36-38)
```markdown
- Assign to each "restricted" messages in Cronos a permission (integer value) and create in Cronos module a mapping between addresses and permissions that is stored in memory. For now, there are only two messages that require permission : MsgUpdateTokenMapping and MsgTurnBridge.
- Create a msg type "MsgUpdatePermissions" that only admin can use and allow to update the address permission mapping.
- Change the logic to always check for the permission before processing the restricted messages.
```

**File:** integration_tests/test_gravity.py (L661-665)
```python
    rsp = cli.turn_bridge("false", from_="community")
    assert rsp["code"] != 0, "should not have the permission"

    rsp = cli.turn_bridge("false", from_="validator")
    assert rsp["code"] == 0, rsp["raw_log"]
```
