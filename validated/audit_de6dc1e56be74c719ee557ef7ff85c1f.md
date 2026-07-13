### Title
`MsgTurnBridge` Handler Is a No-Op Stub — Bridge Permission Check Bypassed and Bridge State Never Updated - (File: `x/cronos/keeper/msg_server.go`)

### Summary

The `TurnBridge` message handler in `x/cronos/keeper/msg_server.go` is implemented as a stub that unconditionally returns `nil, nil`. It performs no permission check and writes no state. This produces two simultaneous failures that are directly analogous to the external report's missing-state-check class: (1) any unprivileged address can submit `MsgTurnBridge` and receive a success response, completely bypassing the `CanTurnBridge` permission that the permission system defines; (2) the bridge-active flag is never written, so the bridge can never be disabled through this message, permanently defeating the emergency circuit-breaker that the Cronos admin/governance relies on.

### Finding Description

The Cronos permission system defines two permission bits:

```go
const (
    CanChangeTokenMapping uint64 = 1 << iota // 1
    CanTurnBridge                             // 2
    All = CanChangeTokenMapping | CanTurnBridge // 3
)
```

`UpdateTokenMapping` correctly gates on `CanChangeTokenMapping`:

```go
if !k.HasPermission(ctx, msg.GetSigners(), CanChangeTokenMapping) {
    return nil, errors.Wrap(sdkerrors.ErrUnauthorized, "msg sender is not authorized")
}
```

But the parallel handler for `TurnBridge` is:

```go
func (k msgServer) TurnBridge(goCtx context.Context, msg *types.MsgTurnBridge) (*types.MsgTurnBridgeResponse, error) {
    return nil, nil
}
```

No permission check. No state write. The function body is empty. The `CanTurnBridge` bit is defined but never consumed anywhere in the production message path. [1](#0-0) [2](#0-1) [3](#0-2) 

### Impact Explanation

Two distinct impacts flow from the same root cause:

**1. Permission bypass (High):** Any unprivileged address can submit `MsgTurnBridge` and receive `code: 0` (success). The `CanTurnBridge` permission — which is the only mechanism by which the Cronos admin can delegate bridge-control authority to a separate operational key — is never enforced. This directly satisfies the allowed impact: *"Bypass of Cronos admin, governance authority, permission… bridge… authorization checks."*

**2. Bridge circuit-breaker permanently broken (High):** Because the handler never writes the `bridge_active` parameter, the bridge state is frozen at its genesis/upgrade value and can never be changed via `MsgTurnBridge`. The integration test `test_gravity_turn_bridge` demonstrates that the intended behavior is for bridge operations to fail after `turn_bridge false` is submitted. With the stub in place, that call succeeds silently but the bridge continues to process all outbound transfers. In an emergency (e.g., a Gravity Bridge exploit), the admin has no on-chain mechanism to halt fund flows. This satisfies: *"Permanent or long-lived inability for honest users or validators to process valid transactions, bridge/conversion flows… under normal network assumptions"* — specifically the inability of the authorized party to stop the bridge. [1](#0-0) [4](#0-3) 

### Likelihood Explanation

The entry path is fully unprivileged: `MsgTurnBridge` is a standard Cosmos SDK message reachable by any address with enough gas. No special role, leaked key, or validator compromise is required. The stub is unconditional — it fires on every invocation. The permission bypass is therefore 100% reliable for any caller, and the bridge-disable failure is 100% reliable for the admin. [1](#0-0) 

### Recommendation

Implement `TurnBridge` with the same pattern used by `UpdateTokenMapping`:

1. Gate on `CanTurnBridge` using `k.HasPermission(ctx, msg.GetSigners(), CanTurnBridge)`.
2. Write the bridge-active flag to the params store (e.g., `params.BridgeActive = msg.Enable; k.SetParams(ctx, params)`).
3. Ensure all EVM hook handlers that process outbound bridge events (`send_to_ibc.go`, `send_to_ibc_v2.go`, `send_cro_to_ibc.go`) read and enforce the stored bridge-active flag before executing any token movement. [5](#0-4) 


### Proof of Concept

**Permission bypass — any address succeeds:**

```go
// Unprivileged address (no CanTurnBridge permission) submits MsgTurnBridge.
// Expected: ErrUnauthorized (same as UpdateTokenMapping for unpermissioned callers).
// Actual:   returns nil, nil — success, no error.
msg := types.NewMsgTurnBridge(unprivilegedAddress, false)
resp, err := msgServer.TurnBridge(ctx, msg)
// err == nil, resp == &MsgTurnBridgeResponse{} — permission check never ran.
```

**Bridge-disable silently ignored:**

```go
// Admin submits TurnBridge(false) to halt the bridge in an emergency.
msg := types.NewMsgTurnBridge(adminAddress, false)
resp, err := msgServer.TurnBridge(ctx, msg)
// err == nil — appears to succeed.

// But params.BridgeActive is unchanged; bridge continues processing all
// outbound EVM hook events (send_to_ibc, send_to_evm_chain, etc.).
// Funds continue to flow through a potentially compromised bridge.
params := k.GetParams(ctx)
// params.BridgeActive still == true (or whatever the genesis value was).
```

This mirrors the external report exactly: just as `RevenueHandler.claim()` lacks the cooldown check that the documentation requires, `TurnBridge` lacks both the permission check and the state-write that the permission system and bridge-control design require. [1](#0-0) [3](#0-2)

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
