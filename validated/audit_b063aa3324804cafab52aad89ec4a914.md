### Title
`MsgTurnBridge` Handler Is a No-Op Stub: Bridge Circuit Breaker Completely Non-Functional — (`File: x/cronos/keeper/msg_server.go`)

### Summary

The `TurnBridge` message handler in `x/cronos/keeper/msg_server.go` is implemented as a bare stub that performs no permission check and updates no state. Any address — privileged or unprivileged — can call `MsgTurnBridge` and receive a success response, while the bridge's `bridge_active` flag is never modified. The intended emergency circuit breaker for the Gravity Bridge is silently broken.

### Finding Description

The `MsgTurnBridge` message is the designated mechanism for disabling the Gravity Bridge in an emergency (documented in ADR-009 and the permission system). The `UpdateTokenMapping` handler correctly enforces `CanChangeTokenMapping` before acting:

```go
// UpdateTokenMapping implements the grpc method
func (k msgServer) UpdateTokenMapping(...) (...) {
    if !k.HasPermission(ctx, msg.GetSigners(), CanChangeTokenMapping) {
        return nil, errors.Wrap(sdkerrors.ErrUnauthorized, "msg sender is not authorized")
    }
    ...
}
``` [1](#0-0) 

By contrast, the `TurnBridge` handler is:

```go
// TurnBridge implements the grpc method
func (k msgServer) TurnBridge(goCtx context.Context, msg *types.MsgTurnBridge) (*types.MsgTurnBridgeResponse, error) {
    return nil, nil
}
``` [2](#0-1) 

Two distinct failures are present:

1. **No permission check**: The `CanTurnBridge` permission (defined alongside `CanChangeTokenMapping`) is never consulted. Any unprivileged address can submit `MsgTurnBridge` and receive a success response, bypassing the access control system entirely. [3](#0-2) 

2. **No state mutation**: The handler never reads or writes the `bridge_active` parameter. The Gravity Bridge module's active flag is never toggled, so the bridge cannot be disabled regardless of who calls the message. [4](#0-3) 

The proto definition and the permission system both treat `MsgTurnBridge` as a real, guarded operation: [5](#0-4) [6](#0-5) 

### Impact Explanation

**High — Bypass of Cronos bridge authorization checks and permanent inability to disable the bridge.**

- Any unprivileged user can call `MsgTurnBridge` and receive a success response, bypassing the `CanTurnBridge` permission gate.
- More critically, even a legitimately permissioned address (admin or delegated operator) invoking `TurnBridge(false)` during an active exploit will observe a successful transaction while the bridge continues operating. The silent no-op means the emergency circuit breaker provides no protection.
- This directly maps to the allowed High impact: *"Bypass of Cronos admin, governance authority, permission, token-mapping, bridge, block-list, or module-account authorization checks."*

### Likelihood Explanation

The entry path is fully reachable by any unprivileged user via the standard `MsgTurnBridge` Cosmos SDK message. No special privileges, leaked keys, or cryptographic breaks are required. The bypass is unconditional — every call to `TurnBridge` hits the stub regardless of sender. [2](#0-1) 

### Recommendation

Implement `TurnBridge` with the same pattern as `UpdateTokenMapping`:

1. Check `CanTurnBridge` permission via `k.HasPermission(ctx, msg.GetSigners(), CanTurnBridge)` and return `ErrUnauthorized` on failure.
2. Read the current Gravity Bridge params, set `bridge_active = msg.Enable`, and persist the updated params.
3. Emit an appropriate event.

### Proof of Concept

1. Any address submits `MsgTurnBridge{Sender: <any_address>, Enable: false}`.
2. The handler at `msg_server.go:85` returns `nil, nil` — the transaction is accepted on-chain with code 0.
3. The Gravity Bridge `bridge_active` parameter remains `true`; `send_to_evm_chain` and `send_to_cosmos` operations continue to succeed.
4. A permissioned admin attempting to halt the bridge during an active exploit (e.g., a malicious supply attack as tested in `test_gravity_detect_malicious_supply`) receives a false success signal while the bridge remains live. [2](#0-1) [3](#0-2)

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
