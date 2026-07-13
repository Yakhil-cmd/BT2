### Title
Missing Permission Check and No-Op Implementation in `TurnBridge` Permanently Disables Bridge Circuit Breaker — (`File: x/cronos/keeper/msg_server.go`)

---

### Summary

The `TurnBridge` message handler in `x/cronos/keeper/msg_server.go` is a stub that returns `nil, nil` with no permission check and no state change. This is a direct analog to the RabbitHole `onlyMinter` bug class: a guard that is supposed to enforce authorization and perform a privileged action does neither. The result is a permanently broken bridge circuit breaker — no one, including the admin, can ever turn the bridge off.

---

### Finding Description

`MsgTurnBridge` is explicitly documented in ADR-009 as a **restricted, permissioned message** requiring the `CanTurnBridge` permission bit. The `UpdateTokenMapping` handler correctly enforces this pattern:

```go
if !k.HasPermission(ctx, msg.GetSigners(), CanChangeTokenMapping) {
    return nil, errors.Wrap(sdkerrors.ErrUnauthorized, "msg sender is not authorized")
}
``` [1](#0-0) 

However, the `TurnBridge` handler is implemented as a bare stub:

```go
func (k msgServer) TurnBridge(goCtx context.Context, msg *types.MsgTurnBridge) (*types.MsgTurnBridgeResponse, error) {
    return nil, nil
}
``` [2](#0-1) 

Two distinct flaws are present simultaneously:

1. **Missing permission check**: There is no call to `k.HasPermission(ctx, msg.GetSigners(), CanTurnBridge)`. Any unprivileged address can submit `MsgTurnBridge` and receive a success response.

2. **No-op implementation**: The function performs no state mutation. The bridge enabled/disabled flag is never written. Returning `(nil, nil)` signals transaction success to the Cosmos SDK without any effect.

The permission system itself is correctly defined:

```go
const (
    CanChangeTokenMapping uint64 = 1 << iota // 1
    CanTurnBridge                             // 2
    All = CanChangeTokenMapping | CanTurnBridge // 3
)
``` [3](#0-2) 

And `HasPermission` correctly checks both the admin address and the permission bitmask: [4](#0-3) 

The guard exists and works — it is simply never called in `TurnBridge`.

---

### Impact Explanation

**High — Bypass of Cronos admin/bridge authorization checks + permanent inability to halt bridge flows.**

The bridge circuit breaker (`MsgTurnBridge`) is the emergency stop mechanism for the Gravity Bridge and IBC bridge operations. Because the handler is a no-op:

- The admin and any permissioned address can never turn the bridge off, regardless of permissions.
- An active bridge exploit (e.g., a draining attack on the Gravity Bridge or IBC escrow) cannot be halted via the intended circuit breaker path.
- Any unprivileged attacker can spam `MsgTurnBridge` transactions that succeed on-chain, polluting logs and potentially masking legitimate admin attempts.

This matches the allowed impact: **"High: Bypass of Cronos admin, governance authority, permission, token-mapping, bridge, block-list, or module-account authorization checks"** and **"High: Permanent or long-lived inability for honest users or validators to process valid transactions, bridge/conversion flows."**

---

### Likelihood Explanation

The entry path is fully unprivileged: any account can construct and broadcast a `MsgTurnBridge` transaction. The missing permission check means it will always succeed. The broken implementation means the bridge state is never changed regardless of who calls it. No special conditions, leaked keys, or governance compromise are required.

---

### Recommendation

Implement `TurnBridge` with the same pattern used by `UpdateTokenMapping`:

```go
func (k msgServer) TurnBridge(goCtx context.Context, msg *types.MsgTurnBridge) (*types.MsgTurnBridgeResponse, error) {
    ctx := sdk.UnwrapSDKContext(goCtx)
    if !k.HasPermission(ctx, msg.GetSigners(), CanTurnBridge) {
        return nil, errors.Wrap(sdkerrors.ErrUnauthorized, "msg sender is not authorized")
    }
    // set bridge enabled/disabled state in keeper
    k.SetBridgeEnabled(ctx, msg.Enable)
    return &types.MsgTurnBridgeResponse{}, nil
}
```

The permission check must come before any state mutation, mirroring the pattern at [5](#0-4) .

---

### Proof of Concept

```go
// Any unprivileged address can submit MsgTurnBridge and receive success.
// The bridge state is never changed; the circuit breaker is permanently broken.

msg := &types.MsgTurnBridge{
    From:   attackerAddress, // no CanTurnBridge permission
    Enable: false,
}
resp, err := msgServer.TurnBridge(ctx, msg)
// err == nil, resp == nil  →  tx succeeds, bridge state unchanged
// Admin also cannot turn bridge off — same no-op result
```

The `CanTurnBridge` permission constant is defined at [6](#0-5)  but is never referenced in the `TurnBridge` handler at [2](#0-1) .

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
