### Title
`TurnBridge` Circuit Breaker Is a No-Op — Admin Cannot Disable the Gravity Bridge in an Emergency - (File: x/cronos/keeper/msg_server.go)

### Summary
The Cronos module defines a `MsgTurnBridge` message and a `CanTurnBridge` permission specifically to allow an admin or permissioned address to act as an emergency circuit breaker for the Gravity Bridge. However, the `TurnBridge` handler in `msg_server.go` is an empty stub that returns `nil, nil` without performing any state change. The bridge circuit breaker is permanently non-functional: no privileged address can ever disable the bridge.

### Finding Description
ADR-009 explicitly documents two restricted operations: `MsgUpdateTokenMapping` (guarded by `CanChangeTokenMapping`) and `MsgTurnBridge` (guarded by `CanTurnBridge`), the latter being described as a mechanism to "disabling the bridge module in case of emergency."

The `UpdateTokenMapping` handler is fully implemented with a permission check and state mutation. The `TurnBridge` handler, however, is a stub:

```go
// TurnBridge implements the grpc method
func (k msgServer) TurnBridge(goCtx context.Context, msg *types.MsgTurnBridge) (*types.MsgTurnBridgeResponse, error) {
    return nil, nil
}
``` [1](#0-0) 

This is structurally identical to the external bug: a function that should be callable by a privileged role (admin / `CanTurnBridge` permissioned address) is effectively inaccessible because the pathway through the message server performs no action. The permission system for `CanTurnBridge` is fully wired: [2](#0-1) 

The `UpdateTokenMapping` handler correctly gates on `HasPermission`: [3](#0-2) 

But `TurnBridge` skips both the permission check and any bridge state mutation. The `CanTurnBridge` bit is defined, can be granted via `MsgUpdatePermissions`, and is queryable — yet calling `MsgTurnBridge` silently succeeds and changes nothing. [4](#0-3) 

### Impact Explanation
The `TurnBridge` function is the sole programmatic mechanism for an authorized address to halt the Gravity Bridge in an emergency (e.g., an active exploit draining bridged CRO or IBC vouchers). Because the handler is a no-op, the bridge circuit breaker is permanently disabled. This constitutes a **High** impact under the allowed scope: *"Permanent or long-lived inability for honest users or validators to process valid transactions, bridge/conversion flows … under normal network assumptions."* The admin's authority over bridge/conversion flows is permanently nullified, also fitting *"Bypass of Cronos admin … authorization checks."*

### Likelihood Explanation
The bug is present in every deployment of this codebase. Any admin or permissioned address that sends `MsgTurnBridge` will receive a success response while the bridge continues operating unchanged. There is no workaround: no other message or governance path calls the underlying bridge-disable logic through this handler.

### Recommendation
Implement `TurnBridge` to:
1. Verify the sender holds `CanTurnBridge` permission (mirroring the `UpdateTokenMapping` guard).
2. Write a bridge-enabled flag to the KV store (or call the appropriate Gravity Bridge keeper method to halt processing).
3. Have the Gravity Bridge end-blocker / message handlers read this flag and reject bridge transactions when disabled.

```go
func (k msgServer) TurnBridge(goCtx context.Context, msg *types.MsgTurnBridge) (*types.MsgTurnBridgeResponse, error) {
    ctx := sdk.UnwrapSDKContext(goCtx)
    if !k.HasPermission(ctx, msg.GetSigners(), CanTurnBridge) {
        return nil, errors.Wrap(sdkerrors.ErrUnauthorized, "msg sender is not authorized")
    }
    k.SetBridgeEnabled(ctx, msg.Enable)
    return &types.MsgTurnBridgeResponse{}, nil
}
```

### Proof of Concept
1. Admin calls `MsgUpdatePermissions` to grant `CanTurnBridge` to a trusted address.
2. That address submits `MsgTurnBridge{Enable: false}` to halt the bridge during an active exploit.
3. The handler returns `nil, nil` — no state is written, no error is returned.
4. The Gravity Bridge continues processing deposits and withdrawals unimpeded.
5. The admin has no alternative on-chain mechanism to stop bridge flows. [1](#0-0) [5](#0-4) [2](#0-1)

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

**File:** docs/architecture/adr-009.md (L8-12)
```markdown
Some messages in cronos require permissions. For example, changing the mapping to support new CRC20 auto-conversion contracts or disabling the bridge module in case of emergency. Right now, only the admin has the ability to use those messages.
 The admin is a single address defined in cronos space and can be modified through governance. It is usually a multi-sig address shared by multiple trusted parties in order to achieve a higher level of security.

While a single multi-sig admin address was originally implemented with simplicity in mind, realistically it is not practical to rely on a single address to perform all admin tasks.
As those operations could become more frequent (updating the token mapping) or needs to be triggered by external systems (circuit breaker for gravity module), it would be more practical to define a granular permission system which restricts certain operations to only some known addresses.
```
