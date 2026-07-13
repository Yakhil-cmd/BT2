### Title
`MsgTurnBridge` Handler Is a No-Op Stub — Bridge Emergency Stop Is Permanently Broken - (File: x/cronos/keeper/msg_server.go)

### Summary

Cronos defines `MsgTurnBridge` as the emergency circuit-breaker for the gravity bridge. The message is fully proto-defined, CLI-exposed, and permission-gated by design. However, the keeper implementation is a complete no-op stub that performs no permission check, writes no state, and always returns success. The bridge can never be disabled, making the emergency stop mechanism permanently inaccessible — a direct analog to the external report's "pause/unpause functions are inaccessible."

### Finding Description

`MsgTurnBridge` is defined in `proto/cronos/tx.proto` as the mechanism to "disable or enable the gravity bridge." ADR-009 explicitly lists it as one of the two critical restricted messages requiring the `CanTurnBridge` permission. The CLI command `CmdTurnBridge` is wired up and callable.

However, the actual keeper implementation in `x/cronos/keeper/msg_server.go` is:

```go
// TurnBridge implements the grpc method
func (k msgServer) TurnBridge(goCtx context.Context, msg *types.MsgTurnBridge) (*types.MsgTurnBridgeResponse, error) {
    return nil, nil
}
```

This stub:
1. **Performs no permission check** — unlike `UpdateTokenMapping` (line 73: `k.HasPermission(ctx, msg.GetSigners(), CanChangeTokenMapping)`), `TurnBridge` checks nothing.
2. **Writes no state** — no bridge-enabled flag is ever set.
3. **Always returns success** — any sender, privileged or not, gets `code: 0`.

Compare with `UpdateTokenMapping`, which properly enforces `CanChangeTokenMapping`:

```go
func (k msgServer) UpdateTokenMapping(...) {
    if !k.HasPermission(ctx, msg.GetSigners(), CanChangeTokenMapping) {
        return nil, errors.Wrap(sdkerrors.ErrUnauthorized, ...)
    }
    ...
}
```

The `CanTurnBridge` permission constant is defined and the `HasPermission` logic supports it, but `TurnBridge` never calls it.

### Impact Explanation

The gravity bridge emergency stop is permanently broken. In an emergency (e.g., a bridge exploit draining funds), the admin or any permissioned address with `CanTurnBridge` cannot disable the bridge via `MsgTurnBridge` — the call succeeds silently but changes nothing. Bridge/conversion flows involving CRC20/CRC21 tokens and gravity-bridged assets cannot be halted through the intended mechanism, resulting in a permanent inability to stop malicious bridge flows.

This maps to: **High — Permanent or long-lived inability for honest users or validators to process valid transactions, bridge/conversion flows under normal network assumptions**, and **High — Bypass of Cronos bridge authorization checks** (the bridge-disabled state can never be set).

### Likelihood Explanation

The vulnerability is present in every deployment of this codebase. Any attempt by the admin or a `CanTurnBridge`-permissioned address to invoke `MsgTurnBridge` will silently succeed without effect. No special conditions are required to trigger it — the broken state is permanent.

### Recommendation

Implement `TurnBridge` with proper permission enforcement and state persistence, analogous to `UpdateTokenMapping`:

```go
func (k msgServer) TurnBridge(goCtx context.Context, msg *types.MsgTurnBridge) (*types.MsgTurnBridgeResponse, error) {
    ctx := sdk.UnwrapSDKContext(goCtx)
    if !k.HasPermission(ctx, msg.GetSigners(), CanTurnBridge) {
        return nil, errors.Wrap(sdkerrors.ErrUnauthorized, "msg sender is not authorized")
    }
    // persist bridge enabled/disabled state
    k.SetBridgeEnabled(ctx, msg.Enable)
    return &types.MsgTurnBridgeResponse{}, nil
}
```

All bridge-processing paths (EVM hooks, gravity end-blocker) must then gate on this stored flag.

### Proof of Concept

1. Any address (privileged or not) submits `MsgTurnBridge{Sender: attacker, Enable: false}`.
2. The handler at `x/cronos/keeper/msg_server.go:85-87` executes `return nil, nil` — no error, no state change.
3. The bridge-enabled flag is never written; the bridge remains active.
4. The admin's emergency stop is silently swallowed. Bridge exploitation continues unimpeded.

**Root cause — stub implementation:** [1](#0-0) 

**Contrast — `UpdateTokenMapping` properly enforces permission:** [2](#0-1) 

**`CanTurnBridge` permission constant defined but never used in handler:** [3](#0-2) 

**ADR-009 explicitly designates `MsgTurnBridge` as a critical restricted message:** [4](#0-3) 

**Proto definition confirms intended semantics:** [5](#0-4)

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
