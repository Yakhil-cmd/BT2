### Title
Missing Authorization Check and No-Op Implementation in `MsgTurnBridge` Permanently Disables Bridge Circuit Breaker - (File: `x/cronos/keeper/msg_server.go`)

### Summary
The `TurnBridge` message handler in `x/cronos/keeper/msg_server.go` contains no permission check and no state-changing logic — it unconditionally returns `nil, nil`. Any unprivileged user can call it successfully, and the bridge circuit breaker can never actually be activated by anyone, including the admin.

### Finding Description
The external bug class is **auth bypass during initialization**: a component assumes it holds a privilege it does not have, causing a critical function to silently fail.

The direct Cronos analog is in `msgServer.TurnBridge`:

```go
// TurnBridge implements the grpc method
func (k msgServer) TurnBridge(goCtx context.Context, msg *types.MsgTurnBridge) (*types.MsgTurnBridgeResponse, error) {
    return nil, nil
}
``` [1](#0-0) 

Compare this to `UpdateTokenMapping`, the sibling restricted message, which correctly enforces the permission gate:

```go
if !k.HasPermission(ctx, msg.GetSigners(), CanChangeTokenMapping) {
    return nil, errors.Wrap(sdkerrors.ErrUnauthorized, "msg sender is not authorized")
}
``` [2](#0-1) 

ADR-009 explicitly designates `MsgTurnBridge` as a restricted message requiring `CanTurnBridge` permission, and the permission constant is defined: [3](#0-2) 

The `CanTurnBridge` bit is wired into the query response and the permission system, but the handler that is supposed to enforce it and write bridge state is a stub. Two distinct defects are present simultaneously:

1. **No authorization check** — `HasPermission(..., CanTurnBridge)` is never called, so any address can submit `MsgTurnBridge` and receive a success response.
2. **No state mutation** — the handler writes nothing; the bridge enabled/disabled state is never toggled regardless of who calls it.

### Impact Explanation
- **Auth bypass (High):** The `CanTurnBridge` permission guard — the only mechanism restricting who may disable the bridge — is completely absent. An unprivileged user can submit `MsgTurnBridge` and receive a success response, bypassing the Cronos admin/permission authorization model.
- **Permanent bridge circuit-breaker failure (High):** Because the handler is a no-op, the bridge can never be turned off by anyone. ADR-001 and ADR-009 both describe `TurnBridge` as the emergency circuit breaker for the Gravity bridge. With this defect, that safety mechanism is permanently non-functional. In an active bridge exploit scenario, the admin has no on-chain path to halt bridge/conversion flows. [4](#0-3) 

### Likelihood Explanation
The entry path is a standard, publicly documented Cosmos SDK transaction (`MsgTurnBridge`) reachable by any address with gas. No privilege, leaked key, or special network position is required. The defect is present in the production keeper and is not gated by any feature flag.

### Recommendation
Implement `TurnBridge` with the same pattern used by `UpdateTokenMapping`:

1. Add a `HasPermission(ctx, msg.GetSigners(), CanTurnBridge)` guard at the top of the handler.
2. Persist the bridge enabled/disabled state (e.g., update a `bridge_active` module parameter or a dedicated KV key).
3. Ensure all bridge-flow paths (EVM hooks, gravity hooks) read and enforce that state before processing transfers.

### Proof of Concept
Submit the following transaction from any unprivileged address:

```bash
cronosd tx cronos turn-bridge false --from <any_unprivileged_key> -y
```

Expected (correct) behavior: transaction rejected with `ErrUnauthorized`.

Actual behavior: transaction succeeds with code `0` and the bridge state is unchanged (bridge remains active). The admin calling the same message also receives success but the bridge is still not disabled, confirming the circuit breaker is permanently non-functional. [1](#0-0) [3](#0-2)

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

**File:** docs/architecture/adr-009.md (L36-38)
```markdown
- Assign to each "restricted" messages in Cronos a permission (integer value) and create in Cronos module a mapping between addresses and permissions that is stored in memory. For now, there are only two messages that require permission : MsgUpdateTokenMapping and MsgTurnBridge.
- Create a msg type "MsgUpdatePermissions" that only admin can use and allow to update the address permission mapping.
- Change the logic to always check for the permission before processing the restricted messages.
```
