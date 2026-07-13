### Title
`MsgTurnBridge` Handler Is a No-Op With No Auth Check, Permanently Disabling Bridge Emergency Stop - (File: x/cronos/keeper/msg_server.go)

### Summary
The `TurnBridge` message handler in `x/cronos/keeper/msg_server.go` unconditionally returns `nil, nil` — it performs no state change and enforces no access control. The `CanTurnBridge` permission bit is defined and the ADR-009 permission system explicitly designates `MsgTurnBridge` as a restricted operation, but the implementation is a silent no-op. Any unprivileged sender can call it without error, and no one — including the admin — can ever actually turn the bridge off.

### Finding Description
`MsgTurnBridge` is a proto-defined Cosmos SDK message reachable by any unprivileged account via the standard transaction path. Its handler is:

```go
// TurnBridge implements the grpc method
func (k msgServer) TurnBridge(goCtx context.Context, msg *types.MsgTurnBridge) (*types.MsgTurnBridgeResponse, error) {
    return nil, nil
}
``` [1](#0-0) 

The permission system defines `CanTurnBridge` as a distinct permission bit and ADR-009 explicitly lists `MsgTurnBridge` as one of the two messages that must be restricted: [2](#0-1) 

Every other sensitive message handler enforces a guard — `UpdateTokenMapping` calls `HasPermission(ctx, msg.GetSigners(), CanChangeTokenMapping)`, `UpdatePermissions` checks `admin != msg.From`, and `StoreBlockList` does the same — but `TurnBridge` has no guard at all and writes nothing to state. [3](#0-2) 

The proto definition confirms the message is a first-class signed transaction surface: [4](#0-3) 

### Impact Explanation
The bridge emergency-stop mechanism is permanently broken. Because the handler is a no-op, the `enable` field is never written to state, so the bridge is always effectively "on." In the event of a bridge exploit or critical vulnerability, neither the admin nor any permissioned address can halt bridge/conversion flows. This satisfies the High impact criterion: **permanent inability for honest users or validators to use bridge/conversion flows under normal network assumptions**, and simultaneously constitutes a **bypass of Cronos admin and permission authorization checks** because the `CanTurnBridge` permission is defined but never enforced.

### Likelihood Explanation
The vulnerability is always present — it requires no special conditions, no timing, and no other exploit. Any transaction submitting `MsgTurnBridge` silently succeeds and does nothing. The bridge cannot be stopped by any actor.

### Recommendation
Implement `TurnBridge` to actually read `msg.Enable` and write a bridge-enabled flag to the KV store, and gate the handler behind the existing `CanTurnBridge` permission check, consistent with how `UpdateTokenMapping` is guarded:

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

All bridge-touching keeper paths (`ConvertVouchersToEvmCoins`, `IbcTransferCoins`, EVM hook handlers) must then check this flag before proceeding.

### Proof of Concept
1. Any account submits `MsgTurnBridge{sender: <any address>, enable: false}`.
2. The handler returns `(MsgTurnBridgeResponse{}, nil)` — success — without writing any state.
3. The bridge remains fully operational.
4. The admin submits the same message; same result — the bridge cannot be stopped.
5. A bridge exploit occurs; no on-chain mechanism exists to halt it. [1](#0-0) [5](#0-4)

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
