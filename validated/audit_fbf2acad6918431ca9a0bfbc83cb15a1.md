### Title
`TurnBridge` Message Handler Is a No-Op Stub — Permission Check Bypassed and Bridge State Never Changed - (File: `x/cronos/keeper/msg_server.go`)

### Summary
The `TurnBridge` message handler, which is the designated emergency circuit breaker for the Gravity Bridge, is implemented as a bare stub returning `nil, nil`. It performs no permission check and never modifies the `bridge_active` parameter. Any unprivileged user can submit `MsgTurnBridge` and receive a success response, while the bridge state is never actually changed.

### Finding Description
The external bug's root cause is a guard condition that makes a state-change function permanently ineffective. The direct Cronos analog is in `TurnBridge`:

```go
// TurnBridge implements the grpc method
func (k msgServer) TurnBridge(goCtx context.Context, msg *types.MsgTurnBridge) (*types.MsgTurnBridgeResponse, error) {
	return nil, nil
}
``` [1](#0-0) 

Compare this with `UpdateTokenMapping`, which correctly gates on `HasPermission`:

```go
if !k.HasPermission(ctx, msg.GetSigners(), CanChangeTokenMapping) {
    return nil, errors.Wrap(sdkerrors.ErrUnauthorized, "msg sender is not authorized")
}
``` [2](#0-1) 

The `CanTurnBridge` permission bit exists and is wired into the permission system: [3](#0-2) 

But it is never consulted in `TurnBridge`. The proto definition confirms `MsgTurnBridge` carries an `enable bool` field intended to flip `bridge_active`: [4](#0-3) 

ADR-009 explicitly designates `MsgTurnBridge` as the emergency circuit breaker for the Gravity module: [5](#0-4) 

### Impact Explanation
Two distinct impacts:

1. **Auth bypass (High)**: The `CanTurnBridge` permission guard is completely absent. Any unprivileged address can submit `MsgTurnBridge` and receive a success response (`code == 0`). The entire permission system for this message is bypassed.

2. **Permanent inability to disable the bridge (High)**: The `bridge_active` parameter is never written. The emergency circuit breaker is permanently broken — the bridge cannot be disabled via `MsgTurnBridge` under any circumstances. The only remaining path is a slow governance `MsgUpdateParams`, which defeats the purpose of the dedicated emergency-disable mechanism. This matches the allowed impact: *"Permanent or long-lived inability for honest users or validators to process valid transactions, bridge/conversion flows... under normal network assumptions."*

### Likelihood Explanation
The `TurnBridge` RPC is a registered, publicly callable Cosmos SDK message. Any user with a valid bech32 address and enough gas can submit it. No special access is required. The stub is reachable on every live node.

### Recommendation
Implement `TurnBridge` with the same pattern as `UpdateTokenMapping`:

```go
func (k msgServer) TurnBridge(goCtx context.Context, msg *types.MsgTurnBridge) (*types.MsgTurnBridgeResponse, error) {
    ctx := sdk.UnwrapSDKContext(goCtx)
    if !k.HasPermission(ctx, msg.GetSigners(), CanTurnBridge) {
        return nil, errors.Wrap(sdkerrors.ErrUnauthorized, "msg sender is not authorized")
    }
    params := k.GetParams(ctx)
    params.EnableAutoDeployment = params.EnableAutoDeployment // preserve other fields
    // set bridge_active field
    params.BridgeActive = msg.Enable
    if err := k.SetParams(ctx, params); err != nil {
        return nil, err
    }
    return &types.MsgTurnBridgeResponse{}, nil
}
```

### Proof of Concept
1. Any unprivileged address submits `MsgTurnBridge{Sender: attacker, Enable: false}`.
2. The handler at `x/cronos/keeper/msg_server.go:85-87` returns `nil, nil` immediately.
3. The transaction is included in a block with `code == 0` (success).
4. `bridge_active` in the module params is unchanged — the bridge remains active.
5. The admin/permissioned address also cannot disable the bridge via this message, permanently disabling the emergency circuit breaker. [1](#0-0)

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

**File:** docs/architecture/adr-009.md (L8-12)
```markdown
Some messages in cronos require permissions. For example, changing the mapping to support new CRC20 auto-conversion contracts or disabling the bridge module in case of emergency. Right now, only the admin has the ability to use those messages.
 The admin is a single address defined in cronos space and can be modified through governance. It is usually a multi-sig address shared by multiple trusted parties in order to achieve a higher level of security.

While a single multi-sig admin address was originally implemented with simplicity in mind, realistically it is not practical to rely on a single address to perform all admin tasks.
As those operations could become more frequent (updating the token mapping) or needs to be triggered by external systems (circuit breaker for gravity module), it would be more practical to define a granular permission system which restricts certain operations to only some known addresses.
```
