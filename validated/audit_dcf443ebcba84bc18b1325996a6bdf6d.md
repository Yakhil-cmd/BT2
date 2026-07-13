### Title
`TurnBridge` Message Handler Is a No-Op and Lacks Permission Enforcement — (`File: x/cronos/keeper/msg_server.go`)

---

### Summary

The `TurnBridge` gRPC message handler in `x/cronos/keeper/msg_server.go` is implemented as a stub that unconditionally returns `nil, nil`. It neither enforces the `CanTurnBridge` permission bit nor updates any bridge state. As a result, any unprivileged address can call `MsgTurnBridge` and receive a success response, and the bridge circuit-breaker can never actually be activated regardless of who calls it.

---

### Finding Description

The `TurnBridge` handler is:

```go
// TurnBridge implements the grpc method
func (k msgServer) TurnBridge(goCtx context.Context, msg *types.MsgTurnBridge) (*types.MsgTurnBridgeResponse, error) {
    return nil, nil
}
``` [1](#0-0) 

Compare with `UpdateTokenMapping`, which correctly enforces its corresponding permission bit before doing any work:

```go
func (k msgServer) UpdateTokenMapping(...) {
    if !k.HasPermission(ctx, msg.GetSigners(), CanChangeTokenMapping) {
        return nil, errors.Wrap(sdkerrors.ErrUnauthorized, "msg sender is not authorized")
    }
    ...
}
``` [2](#0-1) 

The `CanTurnBridge` permission constant is defined alongside `CanChangeTokenMapping` in the permissions system:

```go
const (
    CanChangeTokenMapping uint64 = 1 << iota // 1
    CanTurnBridge                             // 2
    All = CanChangeTokenMapping | CanTurnBridge // 3
)
``` [3](#0-2) 

`HasPermission` is fully implemented and would correctly gate the call if invoked: [4](#0-3) 

The proto definition and CLI both expose `MsgTurnBridge` as a live, publicly-routable message: [5](#0-4) [6](#0-5) 

The integration test `test_gravity_turn_bridge` asserts that an unpermissioned address should be rejected (`code != 0`) and that a permissioned address should succeed and actually disable the bridge: [7](#0-6) 

Neither assertion can hold with the current stub: every caller receives `code == 0` and the bridge state is never changed.

---

### Impact Explanation

**Two distinct High-severity impacts:**

1. **Bypass of bridge authorization checks.** The `CanTurnBridge` permission is defined and assigned to trusted addresses, but the handler never calls `HasPermission`. Any unprivileged address can submit `MsgTurnBridge` and receive a success response, bypassing the intended permission gate. This directly matches the allowed High impact: *"Bypass of Cronos admin, governance authority, permission, token-mapping, bridge, block-list, or module-account authorization checks."*

2. **Permanent inability to disable the Gravity Bridge.** Because the handler is a no-op, the bridge circuit-breaker is permanently non-functional. During a security incident requiring an emergency bridge halt, the admin cannot disable the bridge, leaving all `__CronosSendToEvmChain` / `send_to_evm_chain` flows active and exploitable. This matches: *"Permanent or long-lived inability for honest users or validators to process valid transactions, bridge/conversion flows…"* (from the defender's perspective, the inability to stop the bridge).

---

### Likelihood Explanation

The entry path is fully reachable by any unprivileged address via the standard Cosmos SDK gRPC/REST message surface. No special privileges, leaked keys, or cryptographic breaks are required. The handler is registered in the live service descriptor: [8](#0-7) 

---

### Recommendation

Implement `TurnBridge` to mirror the pattern used by `UpdateTokenMapping`:

1. Check `CanTurnBridge` permission via `k.HasPermission(ctx, msg.GetSigners(), CanTurnBridge)` and return `ErrUnauthorized` on failure.
2. Persist the `Enable` flag to the module's `bridge_active` parameter (or equivalent gravity module parameter) so the bridge state is actually changed.
3. Add unit tests covering both the permission-denied path (unprivileged caller) and the success path (permissioned caller with verified state change).

---

### Proof of Concept

Any address can submit the following transaction and receive `code == 0`:

```
cronosd tx cronos turn-bridge false --from <any_unprivileged_key>
```

The bridge remains active after the call. A permissioned admin calling the same message also receives `code == 0` but the bridge is still not disabled, because the handler performs no state mutation. The `bridge_active` gravity parameter remains `true` regardless of the caller or the `Enable` field value.

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

**File:** proto/cronos/tx.proto (L29-30)
```text
  // TurnBridge defines a method to disable or enable the gravity bridge
  rpc TurnBridge(MsgTurnBridge) returns (MsgTurnBridgeResponse);
```

**File:** x/cronos/client/cli/tx.go (L264-290)
```go
// CmdTurnBridge returns a CLI command handler for enable or disable the bridge
func CmdTurnBridge() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "turn-bridge [true/false]",
		Short: "Turn Bridge",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			clientCtx, err := client.GetClientTxContext(cmd)
			if err != nil {
				return err
			}

			enable, err := strconv.ParseBool(args[0])
			if err != nil {
				return err
			}
			msg := types.NewMsgTurnBridge(clientCtx.GetFromAddress().String(), enable)
			if err := msg.ValidateBasic(); err != nil {
				return err
			}
			return tx.GenerateOrBroadcastTxCLI(clientCtx, cmd.Flags(), msg)
		},
	}

	flags.AddTxFlagsToCmd(cmd)
	return cmd
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

**File:** x/cronos/types/tx.pb.go (L1074-1077)
```go
		{
			MethodName: "TurnBridge",
			Handler:    _Msg_TurnBridge_Handler,
		},
```
