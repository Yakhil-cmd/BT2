### Title
Unprivileged Caller Can Invoke `MsgTurnBridge` and Bridge Circuit Breaker Is Permanently Broken Due to No-Op Handler - (File: `x/cronos/keeper/msg_server.go`)

### Summary

The `TurnBridge` message handler is implemented as a complete stub that performs no permission check and makes no state change. Any unprivileged user can call `MsgTurnBridge` and receive a success response, bypassing the `CanTurnBridge` permission system. Simultaneously, because the handler never writes bridge state, the bridge circuit breaker is permanently non-functional — authorized users cannot disable the Gravity bridge in an emergency.

### Finding Description

ADR-009 explicitly designates `MsgTurnBridge` as a privileged message requiring the `CanTurnBridge` permission bit. The permission system is fully implemented: `CanTurnBridge` is defined, `HasPermission` enforces it, and `UpdateTokenMapping` correctly gates on `CanChangeTokenMapping`. However, the `TurnBridge` handler at line 85–87 is:

```go
// TurnBridge implements the grpc method
func (k msgServer) TurnBridge(goCtx context.Context, msg *types.MsgTurnBridge) (*types.MsgTurnBridgeResponse, error) {
    return nil, nil
}
``` [1](#0-0) 

Compare this to `UpdateTokenMapping`, which correctly enforces its permission:

```go
if !k.HasPermission(ctx, msg.GetSigners(), CanChangeTokenMapping) {
    return nil, errors.Wrap(sdkerrors.ErrUnauthorized, "msg sender is not authorized")
}
``` [2](#0-1) 

The `CanTurnBridge` permission constant is defined and the `HasPermission` function supports it: [3](#0-2) 

The proto definition and integration test both confirm `TurnBridge` is intended to be a privileged, state-changing operation: [4](#0-3) [5](#0-4) 

The integration test asserts `from_="community"` (unprivileged) should fail with `code != 0`, but the no-op handler returns `nil, nil` (success) for every caller regardless of permissions.

### Impact Explanation

Two distinct High impacts:

1. **Bypass of Cronos permission/authorization checks (High):** Any unprivileged address can submit `MsgTurnBridge` and receive a success response (`code == 0`), fully bypassing the `CanTurnBridge` permission gate. This directly satisfies the allowed impact: *"Bypass of Cronos admin, governance authority, permission, token-mapping, bridge, block-list, or module-account authorization checks."*

2. **Permanent inability to disable the Gravity bridge (High):** Because the handler never writes bridge-enabled state, the bridge circuit breaker is permanently non-functional. In an emergency (e.g., a bridge exploit draining user funds), no authorized party — not the admin, not a permissioned address — can halt bridge flows. This satisfies: *"Permanent or long-lived inability for honest users or validators to process valid transactions, bridge/conversion flows."*

### Likelihood Explanation

`MsgTurnBridge` is a standard Cosmos SDK message reachable by any address with a valid bech32 sender. No special setup is required. The missing permission check is unconditional — every call succeeds regardless of the sender's permission bits or admin status.

### Recommendation

Implement the `TurnBridge` handler body to:
1. Check `HasPermission(ctx, msg.GetSigners(), CanTurnBridge)` and return `sdkerrors.ErrUnauthorized` on failure.
2. Write the `msg.Enable` value to the module's KV store so downstream bridge logic can read and enforce the enabled/disabled state.

### Proof of Concept

Any user submits:
```
cronosd tx cronos turn-bridge false --from <any_unprivileged_address>
```

The transaction is accepted on-chain with `code == 0`. The `CanTurnBridge` permission check is never executed. The bridge state is not changed. An authorized admin attempting the same call to disable the bridge in an emergency also receives `code == 0` but the bridge remains active, as no state is written.

### Citations

**File:** x/cronos/keeper/msg_server.go (L73-75)
```go
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

**File:** proto/cronos/tx.proto (L82-89)
```text
message MsgTurnBridge {
  option (cosmos.msg.v1.signer) = "sender";
  string sender                 = 1;
  bool   enable                 = 2;
}

// MsgTurnBridgeResponse defines the response type
message MsgTurnBridgeResponse {}
```

**File:** integration_tests/test_gravity.py (L661-665)
```python
    rsp = cli.turn_bridge("false", from_="community")
    assert rsp["code"] != 0, "should not have the permission"

    rsp = cli.turn_bridge("false", from_="validator")
    assert rsp["code"] == 0, rsp["raw_log"]
```
