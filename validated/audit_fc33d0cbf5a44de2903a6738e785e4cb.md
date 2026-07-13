### Title
`MsgTurnBridge` Handler Is a No-Op With No Permission Check, Permanently Breaking the Bridge Circuit Breaker — (File: `x/cronos/keeper/msg_server.go`)

### Summary
`MsgTurnBridge` is the only on-chain mechanism to disable the Gravity bridge in an emergency. Its handler unconditionally returns `nil, nil` — no permission check, no state write. Any unprivileged account can call it and receive a success response, while the bridge enable/disable state is never updated. The circuit breaker is permanently non-functional.

### Finding Description
`UpdateTokenMapping`, the other privileged bridge-management message, enforces a permission gate before touching state:

```go
// x/cronos/keeper/msg_server.go:69-82
func (k msgServer) UpdateTokenMapping(...) {
    if !k.HasPermission(ctx, msg.GetSigners(), CanChangeTokenMapping) {
        return nil, errors.Wrap(sdkerrors.ErrUnauthorized, "msg sender is not authorized")
    }
    ...
}
```

`TurnBridge`, which is supposed to be the emergency circuit breaker for the same bridge, has neither a permission check nor any state mutation:

```go
// x/cronos/keeper/msg_server.go:84-87
func (k msgServer) TurnBridge(goCtx context.Context, msg *types.MsgTurnBridge) (*types.MsgTurnBridgeResponse, error) {
    return nil, nil
}
```

The asymmetry is exact: one admin-gated bridge-management handler enforces `HasPermission`; the other silently succeeds for every caller and writes nothing.

The proto definition, CLI command (`CmdTurnBridge`), and integration test (`test_gravity_turn_bridge`) all treat `MsgTurnBridge` as a real, permissioned operation that should flip a bridge-enabled flag and cause subsequent `send_to_evm_chain` calls to revert. None of that happens because the handler is a stub.

### Impact Explanation
Two distinct High-severity impacts apply simultaneously:

1. **Bypass of bridge authorization check** — any unprivileged account can submit `MsgTurnBridge` and receive a success response. The permission gate that should mirror `UpdateTokenMapping`'s `HasPermission(CanTurnBridge)` check is entirely absent.

2. **Permanent inability to stop bridge flows** — because the handler never writes the bridge-enabled flag, the Gravity bridge cannot be disabled by anyone, including the admin. In an active bridge exploit, the emergency shutdown path is silently broken: the admin's `MsgTurnBridge` transaction succeeds on-chain but has zero effect, leaving the bridge open and draining assets indefinitely.

### Likelihood Explanation
The bridge circuit breaker is a documented, tested feature. The integration test `test_gravity_turn_bridge` explicitly expects `send_to_evm_chain` to fail after `turn_bridge false` succeeds. Any operator who relies on this mechanism during an incident will find it non-functional. The unprivileged call path requires only a funded account and knowledge of the message type.

### Recommendation
Implement `TurnBridge` with the same pattern as `UpdateTokenMapping`:

1. Check `HasPermission(ctx, msg.GetSigners(), CanTurnBridge)` and return `ErrUnauthorized` on failure.
2. Persist the `enable` flag to the module's `Params` (or a dedicated store key).
3. In every EVM hook that processes `__CronosSendToEvmChain` / `__CronosSendToIbc`, read the flag and return an error if the bridge is disabled.

### Proof of Concept
```
# Any unprivileged account succeeds:
cronosd tx cronos turn-bridge false --from attacker --chain-id cronos_777-1

# Response: code 0 (success) — no permission check fires.
# Bridge state: unchanged — send_to_evm_chain still succeeds.
# Admin attempt: identical result — bridge cannot be turned off.
``` [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3)

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
