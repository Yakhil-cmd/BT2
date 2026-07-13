### Title
`TurnBridge` Is a No-Op Stub: Permission Bypass and Permanent Circuit-Breaker Failure — (`x/cronos/keeper/msg_server.go`)

### Summary

`msgServer.TurnBridge` is implemented as a bare `return nil, nil` stub. It performs no permission check and mutates no state. Any address — privileged or not — can submit `MsgTurnBridge` and receive a success response, while the gravity bridge's `bridge_active` parameter is never changed. The circuit-breaker is permanently non-functional.

### Finding Description

`TurnBridge` at line 85–87 of `x/cronos/keeper/msg_server.go` is:

```go
func (k msgServer) TurnBridge(goCtx context.Context, msg *types.MsgTurnBridge) (*types.MsgTurnBridgeResponse, error) {
    return nil, nil
}
``` [1](#0-0) 

Compare this to `UpdateTokenMapping`, which correctly gates on `HasPermission(ctx, msg.GetSigners(), CanChangeTokenMapping)`: [2](#0-1) 

The `CanTurnBridge` permission bit is defined and the `HasPermission` helper exists, but neither is invoked in `TurnBridge`: [3](#0-2) 

The integration test `test_gravity_turn_bridge` documents the intended behavior explicitly:

- `turn_bridge("false", from_="community")` → `code != 0` (must be rejected — no permission)
- `turn_bridge("false", from_="validator")` → `code == 0` and bridge operations subsequently fail [4](#0-3) 

With the stub, both calls return success and the gravity `bridge_active` parameter is never written.

### Impact Explanation

Two distinct impacts:

1. **Authorization bypass (High):** Any unprivileged address can submit `MsgTurnBridge` and receive a success response without holding `CanTurnBridge` permission. The permission system for this message is completely absent.

2. **Permanent circuit-breaker failure (High):** Even a legitimately authorized caller cannot disable the bridge. The gravity `bridge_active` flag — which the ADR explicitly describes as the mechanism to "disable [the bridge] if necessary" — is never set. [5](#0-4) 

This means that in an emergency (e.g., a bridge exploit draining funds), the intended on-chain circuit-breaker cannot be activated via `MsgTurnBridge`, permanently preventing the bridge from being halted through this path.

### Likelihood Explanation

The path is trivially reachable: any account with enough gas can broadcast a `MsgTurnBridge` transaction. The stub is in production code, not behind a feature flag. The integration test that would catch this is in the test suite (excluded from scope) but the production handler is the bug.

### Recommendation

Implement `TurnBridge` with:
1. A `HasPermission(ctx, msg.GetSigners(), CanTurnBridge)` guard (mirroring `UpdateTokenMapping`).
2. A call to the gravity keeper to set `bridge_active` to `msg.Enable` in the gravity module params.

### Proof of Concept

```go
// Unit test sketch
func TestTurnBridgeIsNoOp(t *testing.T) {
    // setup keeper with a sender that has NO CanTurnBridge permission
    ctx, k := setupKeeper(t)
    unprivileged := sdk.AccAddress([]byte("unprivileged_____"))

    msg := types.NewMsgTurnBridge(unprivileged.String(), false)
    resp, err := msgServer{k}.TurnBridge(ctx, msg)

    // Current behavior: succeeds silently
    require.NoError(t, err)   // PASSES — no permission check
    require.NotNil(t, resp)

    // Bridge state is unchanged — bridge_active is still true
    // gravityParams := k.gravityKeeper.GetParams(ctx)
    // require.True(t, gravityParams.BridgeActive) // never mutated
}
``` [1](#0-0) [6](#0-5)

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

**File:** integration_tests/test_gravity.py (L660-680)
```python
    # turn off bridge
    rsp = cli.turn_bridge("false", from_="community")
    assert rsp["code"] != 0, "should not have the permission"

    rsp = cli.turn_bridge("false", from_="validator")
    assert rsp["code"] == 0, rsp["raw_log"]
    wait_for_new_blocks(cli, 1)

    if gravity.cronos.enable_auto_deployment:
        # send it back to erc20, should fail
        tx = crc21_contract.functions.send_to_evm_chain(
            ADDRS["validator"], amount, 1, 0, b""
        ).build_transaction({"from": ADDRS["community"]})
        txreceipt = send_transaction(cronos_w3, tx, KEYS["community"])
        assert txreceipt.status == 0, "should fail"
    else:
        # send back the gravity native tokens, should fail
        rsp = cli.send_to_ethereum(
            ADDRS["validator"], f"{amount}{denom}", f"0{denom}", from_="community"
        )
        assert rsp["code"] == 3, rsp["raw_log"]
```

**File:** docs/architecture/adr-001.md (L42-42)
```markdown
The unsafe-experimental flag will be removed from the code base as the module is stable enough to be added to cronos. Moreover, the logic of the gravity module can be controlled through the governance parameter "bridge_active" which still leave us the option to disable it if necessary.
```
