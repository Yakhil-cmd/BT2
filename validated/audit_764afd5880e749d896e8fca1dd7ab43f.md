### Title
Missing Permission Check and No-Op Implementation in `MsgTurnBridge` Handler Bypasses Bridge Authorization and Permanently Disables the Bridge Circuit Breaker - (File: `x/cronos/keeper/msg_server.go`)

### Summary

The `TurnBridge` handler in Cronos's `msgServer` is a stub that unconditionally returns `nil, nil` (success) with no permission check and no state mutation. The `CanTurnBridge` permission constant is explicitly defined in the permission system and is intended to gate this message, but it is never checked. Any unprivileged user can submit `MsgTurnBridge` and receive a success response, while simultaneously the bridge circuit breaker is permanently non-functional — legitimate operators with `CanTurnBridge` permission cannot disable the bridge in an emergency.

### Finding Description

The Cronos permission system defines two privileged operations: `CanChangeTokenMapping` and `CanTurnBridge`. `UpdateTokenMapping` correctly enforces its permission gate:

```go
// x/cronos/keeper/msg_server.go:69-82
func (k msgServer) UpdateTokenMapping(...) {
    if !k.HasPermission(ctx, msg.GetSigners(), CanChangeTokenMapping) {
        return nil, errors.Wrap(sdkerrors.ErrUnauthorized, "msg sender is not authorized")
    }
    ...
}
```

However, `TurnBridge` — the analogous handler for the other privileged operation — is a complete stub:

```go
// x/cronos/keeper/msg_server.go:84-87
func (k msgServer) TurnBridge(goCtx context.Context, msg *types.MsgTurnBridge) (*types.MsgTurnBridgeResponse, error) {
    return nil, nil
}
```

There is no call to `HasPermission(ctx, ..., CanTurnBridge)`, no state write, and no error returned. The message is registered in the gRPC service descriptor and is fully reachable by any on-chain transaction sender.

**Attacker path:**
1. Any unprivileged account constructs a `MsgTurnBridge{Sender: attacker, Enable: false}`.
2. Broadcasts the transaction to the Cronos network.
3. The handler executes, returns `nil, nil` → transaction succeeds with `code == 0`.
4. No permission check is performed; the `CanTurnBridge` guard is completely absent.
5. No bridge state is mutated; the bridge cannot be turned off by anyone.

### Impact Explanation

Two distinct High-severity impacts:

1. **Authorization bypass**: Any unprivileged user can call `MsgTurnBridge` and receive a success response, bypassing the `CanTurnBridge` permission check that the permission system explicitly defines as required. This directly matches the allowed impact: *"High: Bypass of Cronos admin, governance authority, permission, token-mapping, bridge, block-list, or module-account authorization checks."*

2. **Permanent bridge circuit breaker failure**: Because the implementation is a no-op, legitimate operators who hold `CanTurnBridge` permission cannot disable the Gravity bridge in an emergency. The circuit breaker — designed to halt bridge operations during an exploit or incident — is permanently non-functional. This matches: *"High: Permanent or long-lived inability for honest users or validators to process valid transactions, bridge/conversion flows... under normal network assumptions."*

### Likelihood Explanation

The entry point is a standard gRPC message handler reachable by any account with gas. No special privileges, leaked keys, or cryptographic breaks are required. The `MsgTurnBridge` CLI command (`turn-bridge`) is publicly documented and exposed. The bug is trivially exploitable.

### Recommendation

Implement `TurnBridge` with the same pattern as `UpdateTokenMapping`:
1. Check `HasPermission(ctx, msg.GetSigners(), CanTurnBridge)` and return `ErrUnauthorized` if it fails.
2. Implement the actual bridge enable/disable state mutation (write the bridge-enabled flag to the KV store and have EVM hooks and the gravity end-blocker respect it).

### Proof of Concept

```
# Any unprivileged account (e.g., "community") submits MsgTurnBridge
cronosd tx cronos turn-bridge false --from community --chain-id cronos_777-1 -y

# Expected: code != 0 (unauthorized)
# Actual:   code == 0 (success, no permission check, no state change)
```

The integration test at `integration_tests/test_gravity.py:661-662` confirms the intended behavior is rejection for unprivileged callers, but the current stub implementation returns success for everyone while doing nothing.

---

**Relevant code locations:** [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4)

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
