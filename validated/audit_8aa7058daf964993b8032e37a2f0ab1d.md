### Title
`MsgTurnBridge` Handler is a No-Op with No Authorization Check, Permanently Breaking the Bridge Circuit Breaker — (File: `x/cronos/keeper/msg_server.go`)

### Summary
The `TurnBridge` message handler in `x/cronos/keeper/msg_server.go` is implemented as a bare `return nil, nil` stub. It performs no permission check and changes no state. Any unprivileged user can submit `MsgTurnBridge` and receive a success response, while the bridge enabled/disabled state is never actually written. The Gravity Bridge circuit breaker is therefore permanently non-functional: neither the admin nor any permissioned address can disable the bridge.

### Finding Description
ADR-009 explicitly designates `MsgTurnBridge` as a restricted message requiring the `CanTurnBridge` permission bit. The permission system in `permissions.go` defines `CanTurnBridge = 1 << 1 = 2` and `HasPermission` enforces it for `UpdateTokenMapping`. However, the `TurnBridge` handler in `msg_server.go` is:

```go
// TurnBridge implements the grpc method
func (k msgServer) TurnBridge(goCtx context.Context, msg *types.MsgTurnBridge) (*types.MsgTurnBridgeResponse, error) {
    return nil, nil
}
``` [1](#0-0) 

Compare this to `UpdateTokenMapping`, which correctly gates on `HasPermission(ctx, msg.GetSigners(), CanChangeTokenMapping)`: [2](#0-1) 

The permission constants and `HasPermission` logic are sound: [3](#0-2) 

The integration test `test_gravity_turn_bridge` confirms the intended contract: a non-admin call to `turn_bridge` must fail (`code != 0`), and a validator/admin call must succeed and actually disable the bridge so that subsequent bridge operations revert: [4](#0-3) 

Because the handler is a no-op, both the permission check and the state write are absent. The bridge enabled/disabled flag is never toggled.

### Impact Explanation
**High — Bypass of bridge authorization check + permanent inability to disable the Gravity Bridge.**

1. **Auth bypass**: Any unprivileged address can submit `MsgTurnBridge` with `enable=false` or `enable=true` and receive a success response (`code == 0`), fully bypassing the `CanTurnBridge` permission gate that ADR-009 mandates.
2. **Broken circuit breaker**: Because no state is written, the bridge is permanently stuck in its current enabled state. The admin and all permissioned addresses lose the ability to halt the Gravity Bridge in an emergency. If the bridge is being actively exploited (e.g., a vulnerability in the Gravity contract or the relayer), there is no on-chain mechanism to stop asset flow.

This satisfies the allowed High impact: *"Bypass of Cronos admin, governance authority, permission, token-mapping, bridge, block-list, or module-account authorization checks"* and *"Permanent or long-lived inability for honest users or validators to process valid transactions, bridge/conversion flows … under normal network assumptions."*

### Likelihood Explanation
The entry path is a standard signed Cosmos SDK transaction (`/cronos.Msg/TurnBridge`) reachable by any funded address. No special privileges, leaked keys, or cryptographic breaks are required. The stub is present in the production handler file, not a test or mock.

### Recommendation
Implement `TurnBridge` with the same pattern used by `UpdateTokenMapping`:

1. Check `HasPermission(ctx, msg.GetSigners(), CanTurnBridge)` and return `sdkerrors.ErrUnauthorized` on failure.
2. Read the current `Params`, set `params.EnableGravity = msg.Enable` (or the equivalent bridge-enabled field), and persist via `k.SetParams(ctx, params)`.
3. Emit an appropriate event.

Reference the existing `UpdateTokenMapping` handler and the `UpdateParams` handler as implementation templates. [5](#0-4) 

### Proof of Concept

```
# Any unprivileged address can call TurnBridge and receive code=0
cronosd tx cronos turn-bridge false \
  --from <any_unprivileged_key> \
  --chain-id cronos_777-1 -y

# Expected (correct): code != 0, ErrUnauthorized
# Actual:             code == 0, empty response — bridge state unchanged
```

Because the handler returns `nil, nil` unconditionally, the transaction is accepted by all nodes, the bridge state is never written, and the admin's subsequent attempt to disable the bridge via the same message also silently succeeds without effect — leaving the bridge permanently enabled with no on-chain circuit breaker. [1](#0-0) [6](#0-5)

### Citations

**File:** x/cronos/keeper/msg_server.go (L68-100)
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

// TurnBridge implements the grpc method
func (k msgServer) TurnBridge(goCtx context.Context, msg *types.MsgTurnBridge) (*types.MsgTurnBridgeResponse, error) {
	return nil, nil
}

func (k msgServer) UpdateParams(goCtx context.Context, msg *types.MsgUpdateParams) (*types.MsgUpdateParamsResponse, error) {
	if msg.Authority != k.authority {
		return nil, errors.Wrapf(govtypes.ErrInvalidSigner, "invalid authority; expected %s, got %s", k.authority, msg.Authority)
	}

	ctx := sdk.UnwrapSDKContext(goCtx)
	if err := k.SetParams(ctx, msg.Params); err != nil {
		return nil, err
	}

	return &types.MsgUpdateParamsResponse{}, nil
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
