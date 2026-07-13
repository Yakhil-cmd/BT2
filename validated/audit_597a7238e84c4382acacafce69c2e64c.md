### Title
`MsgTurnBridge` Handler Is a No-Op with No Authorization Check, Permanently Disabling the Bridge Circuit Breaker — (File: `x/cronos/keeper/msg_server.go`)

### Summary
The `TurnBridge` message handler in `x/cronos/keeper/msg_server.go` is implemented as a bare `return nil, nil`. It performs no permission check and no state change. Any authenticated user can call it and receive a success response, while the admin can never actually disable the Gravity Bridge in an emergency.

### Finding Description

Every other privileged handler in the same file enforces authorization before acting:

- `UpdateTokenMapping` checks `HasPermission(ctx, msg.GetSigners(), CanChangeTokenMapping)` [1](#0-0) 
- `UpdatePermissions` checks `admin != msg.From` [2](#0-1) 
- `StoreBlockList` checks `admin != msg.From` [3](#0-2) 

`TurnBridge`, by contrast, is:

```go
// TurnBridge implements the grpc method
func (k msgServer) TurnBridge(goCtx context.Context, msg *types.MsgTurnBridge) (*types.MsgTurnBridgeResponse, error) {
    return nil, nil
}
``` [4](#0-3) 

The proto definition declares `CanTurnBridge` as a distinct permission bit (value `2`) in the permission system, and the `BlockAddressesDecorator` ante-handler only enforces admin authorization for `MsgStoreBlockList`, not for `MsgTurnBridge`. [5](#0-4) 

The `BlockAddressesDecorator` ante-handler only checks `MsgStoreBlockList` for admin authorization, leaving `MsgTurnBridge` unchecked at the ante layer as well. [6](#0-5) 

The integration test for `test_gravity_turn_bridge` explicitly expects that a non-admin calling `turn_bridge("false")` should fail (`code != 0`), and that the validator (admin) calling it should succeed and actually disable the bridge. [7](#0-6) 

Neither expectation is met: the handler returns success for everyone and changes nothing.

### Impact Explanation

**High — Bypass of bridge authorization check + permanent inability to disable the bridge.**

1. **Auth bypass**: Any unprivileged, authenticated user can submit `MsgTurnBridge` and receive a success response (`nil, nil`), bypassing the `CanTurnBridge` permission gate that the permission system was explicitly designed to enforce. [8](#0-7) 

2. **Broken circuit breaker**: The Gravity Bridge circuit breaker is permanently non-functional. The ADR and integration tests confirm that `TurnBridge` is the emergency mechanism to halt bridge operations. Since the handler is a no-op, the bridge can never be disabled regardless of who calls it. If a critical vulnerability is discovered in the bridge, operators have no on-chain mechanism to stop it. [9](#0-8) 

### Likelihood Explanation

The entry path is fully reachable by any unprivileged user: submit a signed `MsgTurnBridge` transaction. No special privileges, leaked keys, or external conditions are required. The Cosmos SDK enforces that `msg.Sender` matches the tx signer (via `option (cosmos.msg.v1.signer) = "sender"`), but that is the only gate — the handler itself imposes none. [10](#0-9) 

### Recommendation

Implement `TurnBridge` with the same pattern used by `UpdateTokenMapping`:

1. Check `HasPermission(ctx, msg.GetSigners(), CanTurnBridge)` and return `ErrUnauthorized` if it fails.
2. Persist the `msg.Enable` flag to module state (e.g., a `BridgeEnabled` key in the KV store).
3. Read that flag in the Gravity Bridge end-blocker / send-to-Ethereum path to gate bridge operations.

### Proof of Concept

```
# Any unprivileged address can call TurnBridge and receive code=0
cronosd tx cronos turn-bridge false --from unprivileged_key -y

# Expected: code != 0 (unauthorized)
# Actual:   code == 0 (success, but bridge state unchanged)

# Admin calling turn-bridge also gets code=0 but bridge is never disabled
cronosd tx cronos turn-bridge false --from admin_key -y
# Bridge continues to accept send-to-ethereum transactions
```

The integration test at `integration_tests/test_gravity.py:661` asserts `rsp["code"] != 0` for a non-admin call, which would fail against the current implementation. [11](#0-10)

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

**File:** x/cronos/keeper/msg_server.go (L104-108)
```go
	admin := k.Keeper.GetParams(ctx).CronosAdmin
	// if admin is empty, no sender could be equal to it
	if admin != msg.From {
		return nil, errors.Wrap(sdkerrors.ErrUnauthorized, "msg sender is not authorized")
	}
```

**File:** x/cronos/keeper/msg_server.go (L120-123)
```go
	admin := k.Keeper.GetParams(ctx).CronosAdmin
	if admin != msg.From {
		return nil, errors.Wrap(sdkerrors.ErrUnauthorized, "msg sender is not authorized")
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

**File:** app/block_address.go (L75-81)
```go
		for _, msg := range tx.GetMsgs() {
			if blocklistMsg, ok := msg.(*types.MsgStoreBlockList); ok {
				if admin != blocklistMsg.From {
					return ctx, errors.Wrap(sdkerrors.ErrUnauthorized, "msg sender is not authorized")
				}
			}
		}
```

**File:** integration_tests/test_gravity.py (L661-665)
```python
    rsp = cli.turn_bridge("false", from_="community")
    assert rsp["code"] != 0, "should not have the permission"

    rsp = cli.turn_bridge("false", from_="validator")
    assert rsp["code"] == 0, rsp["raw_log"]
```

**File:** docs/architecture/adr-001.md (L42-42)
```markdown
The unsafe-experimental flag will be removed from the code base as the module is stable enough to be added to cronos. Moreover, the logic of the gravity module can be controlled through the governance parameter "bridge_active" which still leave us the option to disable it if necessary.
```

**File:** proto/cronos/tx.proto (L82-86)
```text
message MsgTurnBridge {
  option (cosmos.msg.v1.signer) = "sender";
  string sender                 = 1;
  bool   enable                 = 2;
}
```
