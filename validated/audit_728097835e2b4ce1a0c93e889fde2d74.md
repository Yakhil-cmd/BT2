### Title
`MsgTurnBridge` Handler Is a No-Op: Bridge Circuit Breaker Permanently Non-Functional and `CanTurnBridge` Permission Check Bypassed - (File: `x/cronos/keeper/msg_server.go`)

### Summary

The `TurnBridge` message handler in `x/cronos/keeper/msg_server.go` is implemented as a complete no-op (`return nil, nil`). It performs no permission check and mutates no state. This is the direct Cronos analog to the external report: a documented, permission-gated security control (the bridge circuit breaker) that is entirely absent from the production code. Any unprivileged user can call `MsgTurnBridge` and receive a success response, bypassing the `CanTurnBridge` authorization check. Simultaneously, even the admin cannot actually disable the bridge, rendering the emergency circuit breaker permanently non-functional.

### Finding Description

ADR-009 explicitly specifies that `MsgTurnBridge` is one of exactly two restricted messages requiring the `CanTurnBridge` permission before execution:

> "For now, there are only two messages that require permission: `MsgUpdateTokenMapping` and `MsgTurnBridge`. Change the logic to always check for the permission before processing the restricted messages."

The `CanTurnBridge` permission constant is defined and the permission infrastructure is fully wired:

```go
// x/cronos/keeper/permissions.go
const (
    CanChangeTokenMapping uint64 = 1 << iota // 1
    CanTurnBridge                             // 2
    All = CanChangeTokenMapping | CanTurnBridge // 3
)
```

`UpdateTokenMapping` correctly enforces this pattern:

```go
// x/cronos/keeper/msg_server.go:69-82
func (k msgServer) UpdateTokenMapping(...) (...) {
    if !k.HasPermission(ctx, msg.GetSigners(), CanChangeTokenMapping) {
        return nil, errors.Wrap(sdkerrors.ErrUnauthorized, "msg sender is not authorized")
    }
    ...
}
```

But `TurnBridge` is:

```go
// x/cronos/keeper/msg_server.go:84-87
// TurnBridge implements the grpc method
func (k msgServer) TurnBridge(goCtx context.Context, msg *types.MsgTurnBridge) (*types.MsgTurnBridgeResponse, error) {
    return nil, nil
}
```

There is no `BridgeEnabled` or equivalent state key anywhere in the keeper or types — confirmed by a full-codebase search for `BridgeEnabled`, `bridge_enabled`, `IsBridgeEnabled`, `GetBridgeEnabled`, `SetBridgeEnabled` returning zero results. The function neither checks permissions nor writes any state.

### Impact Explanation

**Dual impact:**

1. **Permission bypass (High):** Any unprivileged user can submit `MsgTurnBridge` and receive a success response (`code = 0`). The `CanTurnBridge` authorization check — which ADR-009 mandates — is completely absent. This directly satisfies: *"High: Bypass of Cronos admin, governance authority, permission, token-mapping, bridge, block-list, or module-account authorization checks."*

2. **Bridge circuit breaker permanently non-functional (High):** Because no bridge-enabled state is ever written, the bridge cannot be turned off under any circumstances. In an active bridge exploit scenario, the admin's emergency stop capability — the primary safeguard described in ADR-009 for the gravity bridge — is permanently inoperative. This satisfies: *"High: Permanent or long-lived inability for honest users or validators to process valid transactions, bridge/conversion flows... under normal network assumptions."*

### Likelihood Explanation

The permission bypass is reachable by any address that can submit a Cosmos SDK transaction — no privilege required. The broken circuit breaker is a latent, always-present condition. The integration test `test_gravity_turn_bridge` explicitly asserts that a non-admin call to `turn_bridge` must fail (`assert rsp["code"] != 0, "should not have the permission"`), confirming the intended behavior is the opposite of what is implemented.

### Recommendation

Implement `TurnBridge` with the same pattern as `UpdateTokenMapping`:

```go
func (k msgServer) TurnBridge(goCtx context.Context, msg *types.MsgTurnBridge) (*types.MsgTurnBridgeResponse, error) {
    ctx := sdk.UnwrapSDKContext(goCtx)

    // Enforce CanTurnBridge permission
    if !k.HasPermission(ctx, msg.GetSigners(), CanTurnBridge) {
        return nil, errors.Wrap(sdkerrors.ErrUnauthorized, "msg sender is not authorized")
    }

    // Persist bridge enabled/disabled state
    k.SetBridgeEnabled(ctx, msg.Enable)

    return &types.MsgTurnBridgeResponse{}, nil
}
```

Add `SetBridgeEnabled` / `GetBridgeEnabled` to the keeper backed by a KV store key, and gate all bridge-outbound paths (gravity end blocker, `send_to_evm_chain` precompile, IBC transfer hooks) on this flag.

### Proof of Concept

1. Any unprivileged address submits `MsgTurnBridge{Sender: attacker, Enable: false}`.
2. The handler at `x/cronos/keeper/msg_server.go:85-87` executes `return nil, nil` — no permission check, no state write.
3. The transaction succeeds with `code = 0`.
4. The bridge state is unchanged (no `BridgeEnabled` key exists anywhere in the store).
5. Simultaneously, the admin submits the same message with `Enable: false` — it also succeeds but writes nothing, so the bridge remains permanently active and cannot be halted. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3)

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
