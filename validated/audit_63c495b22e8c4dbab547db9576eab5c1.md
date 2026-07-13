### Title
Missing Authorization Check and Empty Implementation in `TurnBridge` - (`File: x/cronos/keeper/msg_server.go`)

### Summary

`MsgTurnBridge` is a privileged operation explicitly designed to require the `CanTurnBridge` permission (per ADR-009 and the `CanTurnBridge` constant in the permission system). Its keeper handler performs no authorization check and no state mutation — it unconditionally returns `nil, nil`. Any unprivileged account can submit `MsgTurnBridge` and receive a success response, fully bypassing the Cronos permission guard. Simultaneously, even a legitimately authorized account cannot actually toggle the bridge state, permanently disabling the circuit-breaker mechanism.

### Finding Description

`UpdateTokenMapping` — the sibling restricted message — correctly gates execution behind `HasPermission`:

```go
// x/cronos/keeper/msg_server.go:72-75
if !k.HasPermission(ctx, msg.GetSigners(), CanChangeTokenMapping) {
    return nil, errors.Wrap(sdkerrors.ErrUnauthorized, "msg sender is not authorized")
}
```

`TurnBridge`, which is supposed to carry the same class of restriction (`CanTurnBridge`), is implemented as:

```go
// x/cronos/keeper/msg_server.go:84-87
func (k msgServer) TurnBridge(goCtx context.Context, msg *types.MsgTurnBridge) (*types.MsgTurnBridgeResponse, error) {
    return nil, nil
}
```

No permission check. No state write. The function is a no-op that always succeeds.

ADR-009 explicitly lists `MsgTurnBridge` as one of the two messages that must be restricted to permissioned addresses:

> "For now, there are only two messages that require permission: `MsgUpdateTokenMapping` and `MsgTurnBridge`."

The integration test `test_gravity_turn_bridge` confirms the intended contract — an unauthorized caller (`community`) must be rejected with a non-zero code, and an authorized caller (`validator`) must succeed and actually disable bridge operations. Neither invariant holds with the current implementation.

### Impact Explanation

**Auth bypass (High):** The `CanTurnBridge` permission guard — a core component of the Cronos admin/permission system — is completely absent. Any unprivileged account can submit `MsgTurnBridge` and receive a `code: 0` success response, bypassing the authorization boundary that ADR-009 mandates.

**Bridge circuit-breaker permanently broken:** Because the handler is a no-op, even a legitimately authorized account cannot disable or re-enable the bridge. The emergency circuit-breaker that the permission system was designed to protect is non-functional.

### Likelihood Explanation

The entry path is a standard signed Cosmos SDK transaction (`MsgTurnBridge`) with no preconditions beyond paying gas. Any account on the network can reach it. The bypass is unconditional and requires no special knowledge.

### Recommendation

Apply the same permission guard used by `UpdateTokenMapping`:

```go
func (k msgServer) TurnBridge(goCtx context.Context, msg *types.MsgTurnBridge) (*types.MsgTurnBridgeResponse, error) {
    ctx := sdk.UnwrapSDKContext(goCtx)
    if !k.HasPermission(ctx, msg.GetSigners(), CanTurnBridge) {
        return nil, errors.Wrap(sdkerrors.ErrUnauthorized, "msg sender is not authorized")
    }
    // implement actual bridge state toggle
    ...
}
```

### Proof of Concept

1. Any account submits `MsgTurnBridge{Sender: <unprivileged_addr>, Enable: false}`.
2. The handler at `msg_server.go:85` executes `return nil, nil` — no permission check, no state change.
3. The transaction is committed with `code: 0`.
4. The `CanTurnBridge` permission system is bypassed; the bridge state is unchanged regardless of the caller.

---

**Key references:**

`TurnBridge` no-op handler: [1](#0-0) 

`UpdateTokenMapping` correct permission guard (the pattern `TurnBridge` should follow): [2](#0-1) 

`CanTurnBridge` permission constant definition: [3](#0-2) 

ADR-009 explicitly listing `MsgTurnBridge` as a restricted message: [4](#0-3) 

Integration test confirming the expected authorization behavior: [5](#0-4)

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
