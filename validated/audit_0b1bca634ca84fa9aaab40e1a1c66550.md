### Title
`MsgTurnBridge` Handler Is an Empty Stub — Silent Success with No Permission Check and No State Change - (File: x/cronos/keeper/msg_server.go)

### Summary
`TurnBridge`, the bridge circuit-breaker message handler, is implemented as a no-op that returns `nil, nil` (success) for every caller. It performs no permission check and changes no state. Any unprivileged user can submit `MsgTurnBridge` and receive a success response, while the bridge is never actually toggled. This is a direct analog of the external "fail silently" bug class: a privileged action silently succeeds for unauthorized callers while producing no real effect.

### Finding Description
`msgServer.TurnBridge` in `x/cronos/keeper/msg_server.go` is:

```go
// TurnBridge implements the grpc method
func (k msgServer) TurnBridge(goCtx context.Context, msg *types.MsgTurnBridge) (*types.MsgTurnBridgeResponse, error) {
    return nil, nil
}
``` [1](#0-0) 

Every other privileged message in the same file enforces authorization before acting:

- `UpdateTokenMapping` checks `HasPermission(ctx, msg.GetSigners(), CanChangeTokenMapping)` and returns `ErrUnauthorized` on failure. [2](#0-1) 
- `UpdatePermissions` checks `admin != msg.From` and returns `ErrUnauthorized`. [3](#0-2) 
- `StoreBlockList` checks `admin != msg.From` and returns `ErrUnauthorized`. [4](#0-3) 

ADR-009 explicitly lists `MsgTurnBridge` as one of the two messages that **must** require the `CanTurnBridge` permission:

> "For now, there are only two messages that require permission: MsgUpdateTokenMapping and MsgTurnBridge." [5](#0-4) 

The permission constant `CanTurnBridge` is defined and used in the permission system but is never consulted by the handler: [6](#0-5) 

The proto definition confirms `MsgTurnBridge` is a live, callable RPC endpoint: [7](#0-6) 

### Impact Explanation
Two distinct High-severity impacts arise simultaneously:

1. **Authorization bypass**: Any unprivileged address can submit `MsgTurnBridge` and receive a `code: 0` success response. The `CanTurnBridge` permission check — the only guard protecting the bridge circuit-breaker — is entirely absent. This matches the allowed impact: *"Bypass of Cronos admin, governance authority, permission … bridge … authorization checks."*

2. **Permanent inability to disable the bridge**: Because the handler performs no state change, no caller — including the admin or a permissioned address — can ever disable the Gravity bridge. In an emergency (e.g., an active bridge exploit), the circuit-breaker is permanently non-functional. This matches: *"Permanent or long-lived inability for honest users or validators to process valid transactions, bridge/conversion flows … under normal network assumptions."*

### Likelihood Explanation
The entry path is a standard Cosmos SDK transaction requiring no special access. Any wallet holder on the network can construct and broadcast `MsgTurnBridge`. The vulnerability is unconditional: it fires on every invocation regardless of chain state.

### Recommendation
Implement `TurnBridge` with the same pattern used by `UpdateTokenMapping`:

```go
func (k msgServer) TurnBridge(goCtx context.Context, msg *types.MsgTurnBridge) (*types.MsgTurnBridgeResponse, error) {
    ctx := sdk.UnwrapSDKContext(goCtx)
    if !k.HasPermission(ctx, msg.GetSigners(), CanTurnBridge) {
        return nil, errors.Wrap(sdkerrors.ErrUnauthorized, "msg sender is not authorized")
    }
    // update bridge-enabled param
    params := k.GetParams(ctx)
    params.EnableAutoDeployment = msg.Enable  // or the appropriate bridge-enable field
    if err := k.SetParams(ctx, params); err != nil {
        return nil, err
    }
    return &types.MsgTurnBridgeResponse{}, nil
}
```

### Proof of Concept
1. Obtain any funded address on Cronos (no special permissions required).
2. Construct a `MsgTurnBridge{Sender: <attacker_address>, Enable: false}` transaction.
3. Broadcast it. The chain returns `code: 0` (success) with no error.
4. Query bridge state — it is unchanged; the bridge remains enabled.
5. Repeat with `Enable: true` — same result. The bridge state is immutable via this message.

An authorized validator attempting to disable the bridge in an emergency faces the same outcome: the transaction succeeds but the bridge is never disabled, leaving the Gravity bridge permanently uncontrollable through its designated circuit-breaker path.

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

**File:** x/cronos/keeper/msg_server.go (L102-108)
```go
func (k msgServer) UpdatePermissions(goCtx context.Context, msg *types.MsgUpdatePermissions) (*types.MsgUpdatePermissionsResponse, error) {
	ctx := sdk.UnwrapSDKContext(goCtx)
	admin := k.Keeper.GetParams(ctx).CronosAdmin
	// if admin is empty, no sender could be equal to it
	if admin != msg.From {
		return nil, errors.Wrap(sdkerrors.ErrUnauthorized, "msg sender is not authorized")
	}
```

**File:** x/cronos/keeper/msg_server.go (L118-123)
```go
func (k msgServer) StoreBlockList(goCtx context.Context, msg *types.MsgStoreBlockList) (*types.MsgStoreBlockListResponse, error) {
	ctx := sdk.UnwrapSDKContext(goCtx)
	admin := k.Keeper.GetParams(ctx).CronosAdmin
	if admin != msg.From {
		return nil, errors.Wrap(sdkerrors.ErrUnauthorized, "msg sender is not authorized")
	}
```

**File:** docs/architecture/adr-009.md (L36-38)
```markdown
- Assign to each "restricted" messages in Cronos a permission (integer value) and create in Cronos module a mapping between addresses and permissions that is stored in memory. For now, there are only two messages that require permission : MsgUpdateTokenMapping and MsgTurnBridge.
- Create a msg type "MsgUpdatePermissions" that only admin can use and allow to update the address permission mapping.
- Change the logic to always check for the permission before processing the restricted messages.
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
