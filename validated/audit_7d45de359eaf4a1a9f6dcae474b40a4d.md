### Title
No-Op `TurnBridge` Handler Permanently Disables Bridge Emergency Circuit Breaker - (File: x/cronos/keeper/msg_server.go)

### Summary
The `TurnBridge` message handler is a complete stub that unconditionally returns `(nil, nil)` without performing any permission check, state mutation, or bridge-enable/disable logic. Every call to `MsgTurnBridge` silently succeeds while leaving the bridge state entirely unchanged, making the emergency circuit breaker permanently non-functional.

### Finding Description
The `TurnBridge` function body is:

```go
// TurnBridge implements the grpc method
func (k msgServer) TurnBridge(goCtx context.Context, msg *types.MsgTurnBridge) (*types.MsgTurnBridgeResponse, error) {
    return nil, nil
}
``` [1](#0-0) 

This is the direct Cronos analog of the external "useless assertion" bug class: just as the reported `assertEq` compared `value1` to itself and therefore never enforced anything, `TurnBridge` accepts any call, returns success, and enforces nothing.

Contrast with every other restricted handler in the same file:

- `UpdateTokenMapping` calls `k.HasPermission(ctx, msg.GetSigners(), CanChangeTokenMapping)` and writes state. [2](#0-1) 
- `UpdatePermissions` checks `admin != msg.From` before writing. [3](#0-2) 
- `StoreBlockList` checks `admin != msg.From` before writing. [4](#0-3) 

`TurnBridge` does neither. The `CanTurnBridge` permission bit is defined and tested in the permission system: [5](#0-4) 

but is never consulted by the handler that is supposed to use it.

The `MsgTurnBridge` message type carries a `Sender` and an `Enable` bool: [6](#0-5) 

`ValidateBasic` only validates the sender address format — it does not enforce authorization. The handler is the sole place where authorization and state mutation should occur, and it does neither.

### Impact Explanation
The Gravity Bridge circuit breaker is the primary emergency mechanism for halting bridge operations during an active exploit or oracle manipulation event. With `TurnBridge` being a no-op:

1. The admin or any permissioned address submits `MsgTurnBridge{Enable: false}`.
2. The transaction is accepted on-chain and returns success.
3. No bridge-enabled flag is written to state.
4. All bridge operations (Gravity `send_to_evm_chain`, batch creation, etc.) continue unimpeded.
5. An attacker exploiting a bridge vulnerability can drain funds indefinitely even after the admin has "disabled" the bridge.

The integration test `test_gravity_turn_bridge` explicitly asserts that bridge operations fail after `turn_bridge("false")`: [7](#0-6) 

At runtime this assertion would fail silently at the protocol level — the CLI tx succeeds but the bridge remains live.

This maps to: **High — Bypass of Cronos admin bridge authorization check**, and potentially **Critical** if an active bridge exploit is in progress when the admin attempts to invoke the circuit breaker.

### Likelihood Explanation
No special attacker privileges are required. The attacker simply continues normal bridge usage. The only precondition is that the admin attempts to invoke the circuit breaker (a near-certainty during any bridge security incident). The bypass is unconditional and deterministic.

### Recommendation
Implement `TurnBridge` to:
1. Verify the caller holds `CanTurnBridge` permission via `k.HasPermission(ctx, msg.GetSigners(), CanTurnBridge)`.
2. Persist the `Enable` flag to the KV store (e.g., under a `KeyPrefixBridgeEnabled` key).
3. Have Gravity Bridge hooks and batch-creation logic read this flag and reject operations when the bridge is disabled.

### Proof of Concept
```
1. Attacker begins draining funds via a Gravity Bridge vulnerability.
2. Admin submits: MsgTurnBridge{Sender: <admin>, Enable: false}
3. TurnBridge returns (nil, nil) — tx included in block, no state written.
4. Bridge remains fully operational; attacker's drain continues unimpeded.
5. Admin has no recourse short of a governance upgrade.
```

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

**File:** x/cronos/keeper/msg_server.go (L102-116)
```go
func (k msgServer) UpdatePermissions(goCtx context.Context, msg *types.MsgUpdatePermissions) (*types.MsgUpdatePermissionsResponse, error) {
	ctx := sdk.UnwrapSDKContext(goCtx)
	admin := k.Keeper.GetParams(ctx).CronosAdmin
	// if admin is empty, no sender could be equal to it
	if admin != msg.From {
		return nil, errors.Wrap(sdkerrors.ErrUnauthorized, "msg sender is not authorized")
	}
	acc, err := sdk.AccAddressFromBech32(msg.Address)
	if err != nil {
		return nil, err
	}
	k.SetPermissions(ctx, acc, msg.Permissions)

	return &types.MsgUpdatePermissionsResponse{}, nil
}
```

**File:** x/cronos/keeper/msg_server.go (L118-126)
```go
func (k msgServer) StoreBlockList(goCtx context.Context, msg *types.MsgStoreBlockList) (*types.MsgStoreBlockListResponse, error) {
	ctx := sdk.UnwrapSDKContext(goCtx)
	admin := k.Keeper.GetParams(ctx).CronosAdmin
	if admin != msg.From {
		return nil, errors.Wrap(sdkerrors.ErrUnauthorized, "msg sender is not authorized")
	}
	ctx.KVStore(k.storeKey).Set(types.KeyPrefixBlockList, msg.Blob)
	return &types.MsgStoreBlockListResponse{}, nil
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

**File:** x/cronos/types/messages.go (L125-141)
```go
// NewMsgTurnBridge ...
func NewMsgTurnBridge(admin string, enable bool) *MsgTurnBridge {
	return &MsgTurnBridge{
		Sender: admin,
		Enable: enable,
	}
}

// ValidateBasic ...
func (msg *MsgTurnBridge) ValidateBasic() error {
	_, err := sdk.AccAddressFromBech32(msg.Sender)
	if err != nil {
		return errors.Wrapf(sdkerrors.ErrInvalidAddress, "invalid sender address (%s)", err)
	}

	return nil
}
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
