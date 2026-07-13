### Title
`MsgTurnBridge` Handler Accepts Any Sender Unconditionally and Is a No-Op Stub, Permanently Breaking the Bridge Circuit Breaker — (File: `x/cronos/keeper/msg_server.go`)

### Summary

The `TurnBridge` message handler in `x/cronos/keeper/msg_server.go` is implemented as a bare `return nil, nil` stub. It performs no permission check and mutates no state. Any unprivileged address can submit a `MsgTurnBridge` transaction and receive a success response (code 0), bypassing the `CanTurnBridge` permission gate that ADR-009 and the permissions system explicitly require. Because the handler is a no-op, the bridge circuit breaker is permanently inoperative: neither the admin nor any permissioned address can ever disable bridge flows on-chain.

### Finding Description

`UpdateTokenMapping` — the sibling restricted message — correctly enforces its permission gate:

```go
// x/cronos/keeper/msg_server.go:69-82
func (k msgServer) UpdateTokenMapping(...) (...) {
    if !k.HasPermission(ctx, msg.GetSigners(), CanChangeTokenMapping) {
        return nil, errors.Wrap(sdkerrors.ErrUnauthorized, "msg sender is not authorized")
    }
    ...
}
```

`TurnBridge`, which ADR-009 explicitly lists as the second restricted message requiring `CanTurnBridge`, is instead:

```go
// x/cronos/keeper/msg_server.go:84-87
func (k msgServer) TurnBridge(goCtx context.Context, msg *types.MsgTurnBridge) (*types.MsgTurnBridgeResponse, error) {
    return nil, nil
}
```

No call to `HasPermission`, no call to any keeper method that would write `bridge_active` or any equivalent state. The proto surface is fully wired (`_Msg_TurnBridge_Handler` dispatches to this function), `ValidateBasic` only checks that `Sender` is a valid bech32 address, and the Cosmos SDK ante-handler only verifies the transaction signature — so any funded address can broadcast a valid `MsgTurnBridge` and receive `code: 0`.

The integration test `test_gravity_turn_bridge` asserts:
```python
rsp = cli.turn_bridge("false", from_="community")
assert rsp["code"] != 0, "should not have the permission"
```
This assertion fails against the current implementation because the handler returns success for every caller.

### Impact Explanation

**Two compounding impacts:**

1. **Permission bypass (High):** The `CanTurnBridge` authorization check — the only on-chain gate protecting the bridge circuit breaker — is entirely absent. Any unprivileged address can call `MsgTurnBridge` and receive a success response, satisfying the "Bypass of Cronos admin, governance authority, permission… authorization checks" High-impact criterion.

2. **Permanent inability to disable bridge flows (High):** Because the handler writes no state, the bridge circuit breaker is permanently non-functional. No on-chain transaction — including one from the `CronosAdmin` or a `CanTurnBridge`-permissioned address — can disable bridge flows. In a security incident requiring an emergency stop (e.g., a malicious gravity-bridged token, an oracle manipulation, or a bridge contract exploit), the on-chain kill-switch is inoperative. This satisfies the "Permanent or long-lived inability for honest users or validators to… bridge/conversion flows" High-impact criterion.

### Likelihood Explanation

The entry path is fully reachable by any funded address with no special privileges. `MsgTurnBridge` is a standard Cosmos SDK message exposed via gRPC and the CLI (`cronosd tx cronos turn-bridge`). The only precondition is enough gas to submit the transaction. The bug is deterministic and reproducible on every node running this code.

### Recommendation

Implement `TurnBridge` with the same pattern as `UpdateTokenMapping`:

1. Check `HasPermission(ctx, msg.GetSigners(), CanTurnBridge)` and return `sdkerrors.ErrUnauthorized` on failure.
2. Write the desired bridge-enabled state to the appropriate keeper (gravity bridge `bridge_active` parameter or a dedicated Cronos params field).
3. Emit a corresponding event.

### Proof of Concept

```bash
# Any funded address — no CanTurnBridge permission required
cronosd tx cronos turn-bridge false \
  --from community \
  --chain-id cronos_777-1 \
  --gas auto \
  --gas-prices 5000000000000basetcro \
  -y

# Expected (correct): code != 0, "msg sender is not authorized"
# Actual (buggy):     code == 0, empty MsgTurnBridgeResponse
```

The handler at [1](#0-0)  returns `nil, nil` unconditionally, with no call to `HasPermission` and no state mutation.

Compare with the correctly-guarded sibling at [2](#0-1)  which enforces `CanChangeTokenMapping` before proceeding.

The permission constants and `HasPermission` logic are defined at [3](#0-2) , where `CanTurnBridge` is bit `2` and `All` is `3`.

ADR-009 explicitly lists `MsgTurnBridge` as a restricted message requiring permission enforcement at [4](#0-3) .

The integration test that would catch this regression is at [5](#0-4) , asserting `code != 0` for an unprivileged caller — an assertion the current stub silently violates.

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

**File:** x/cronos/keeper/permissions.go (L13-48)
```go
const (
	CanChangeTokenMapping uint64                                  = 1 << iota // 1
	CanTurnBridge                                                             // 2
	All                   = CanChangeTokenMapping | CanTurnBridge             // 3
)

func (k Keeper) SetPermissions(ctx sdk.Context, address sdk.AccAddress, permissions uint64) {
	store := ctx.KVStore(k.storeKey)
	permissionsBytes := sdk.Uint64ToBigEndian(permissions)
	store.Set(types.AdminToPermissionsKey(address), permissionsBytes)
}

func (k Keeper) GetPermissions(ctx sdk.Context, address sdk.AccAddress) uint64 {
	store := ctx.KVStore(k.storeKey)
	permissionsBytes := store.Get(types.AdminToPermissionsKey(address))
	return sdk.BigEndianToUint64(permissionsBytes)
}

// HasPermission check if an account has a specific permission. by default cronos admin has all permissions
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

**File:** docs/architecture/adr-009.md (L36-38)
```markdown
- Assign to each "restricted" messages in Cronos a permission (integer value) and create in Cronos module a mapping between addresses and permissions that is stored in memory. For now, there are only two messages that require permission : MsgUpdateTokenMapping and MsgTurnBridge.
- Create a msg type "MsgUpdatePermissions" that only admin can use and allow to update the address permission mapping.
- Change the logic to always check for the permission before processing the restricted messages.
```

**File:** integration_tests/test_gravity.py (L661-665)
```python
    rsp = cli.turn_bridge("false", from_="community")
    assert rsp["code"] != 0, "should not have the permission"

    rsp = cli.turn_bridge("false", from_="validator")
    assert rsp["code"] == 0, rsp["raw_log"]
```
