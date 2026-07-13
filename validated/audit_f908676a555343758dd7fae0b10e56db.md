### Title
`MsgTurnBridge` Handler Is a No-Op Stub — Bridge Emergency Circuit Breaker Is Permanently Broken and Permission Check Is Bypassed - (`x/cronos/keeper/msg_server.go`)

### Summary

The `TurnBridge` gRPC message handler, which is the designated emergency circuit breaker for the Gravity Bridge, is implemented as a stub that unconditionally returns `nil, nil` without performing any authorization check or state mutation. Any unprivileged address can call it and receive a success response, while the bridge state is never actually changed. The bridge cannot be disabled in a security emergency.

### Finding Description

The `x/cronos` module defines a full permission system with a `CanTurnBridge` bit, a CLI command `CmdTurnBridge`, and a proto-defined `MsgTurnBridge` message — all explicitly designed to allow an authorized address to disable the Gravity Bridge as an emergency circuit breaker (per ADR-009 and ADR-001).

However, the actual server-side implementation of the handler is:

```go
// TurnBridge implements the grpc method
func (k msgServer) TurnBridge(goCtx context.Context, msg *types.MsgTurnBridge) (*types.MsgTurnBridgeResponse, error) {
    return nil, nil
}
``` [1](#0-0) 

This stub:
1. **Performs no authorization check** — unlike `UpdateTokenMapping`, which calls `k.HasPermission(ctx, msg.GetSigners(), CanChangeTokenMapping)`, `TurnBridge` checks nothing. Any unprivileged address can submit `MsgTurnBridge` and receive a success response.
2. **Mutates no state** — the gravity module's `bridge_active` parameter is never updated, no event is emitted, and no Cronos params are changed.

Compare with `UpdateTokenMapping`, which correctly enforces the permission system:

```go
func (k msgServer) UpdateTokenMapping(...) {
    if !k.HasPermission(ctx, msg.GetSigners(), CanChangeTokenMapping) {
        return nil, errors.Wrap(sdkerrors.ErrUnauthorized, "msg sender is not authorized")
    }
    ...
}
``` [2](#0-1) 

The permission constants and `HasPermission` logic are fully implemented and used elsewhere: [3](#0-2) 

The CLI command and proto definition are also fully wired up: [4](#0-3) [5](#0-4) 

ADR-009 explicitly states `MsgTurnBridge` is one of the two restricted messages requiring the `CanTurnBridge` permission: [6](#0-5) 

### Impact Explanation

Two distinct impacts:

1. **Permission bypass (High):** Any unprivileged address can submit `MsgTurnBridge` and receive a `code: 0` success response. The `CanTurnBridge` permission check — which is the entire purpose of the permission system for this message — is never enforced. This directly bypasses the Cronos admin/governance authority authorization check.

2. **Permanent inability to disable the bridge (High):** The Gravity Bridge emergency circuit breaker is permanently non-functional. In a security incident (e.g., a malicious batch relay, an oracle manipulation, or a supply overflow attack), the admin or a permissioned address cannot disable the bridge via `MsgTurnBridge`. The bridge remains active regardless of what is submitted. This is a long-lived inability to halt bridge/conversion flows under normal network assumptions.

### Likelihood Explanation

The stub is reachable by any address via a standard Cosmos SDK transaction. No special privileges, leaked keys, or cryptographic breaks are required. The CLI command `turn-bridge` is publicly documented and accessible. The integration test `test_gravity_turn_bridge` even asserts that `cli.turn_bridge("false", from_="validator")` returns `code == 0` — which it does, but only because the stub silently succeeds without doing anything. [7](#0-6) 

### Recommendation

Implement `TurnBridge` with the same pattern as `UpdateTokenMapping`:

```go
func (k msgServer) TurnBridge(goCtx context.Context, msg *types.MsgTurnBridge) (*types.MsgTurnBridgeResponse, error) {
    ctx := sdk.UnwrapSDKContext(goCtx)
    if !k.HasPermission(ctx, msg.GetSigners(), CanTurnBridge) {
        return nil, errors.Wrap(sdkerrors.ErrUnauthorized, "msg sender is not authorized")
    }
    // update gravity bridge_active parameter
    params := k.gravityKeeper.GetParams(ctx)
    params.BridgeActive = msg.Enable
    k.gravityKeeper.SetParams(ctx, params)
    return &types.MsgTurnBridgeResponse{}, nil
}
```

### Proof of Concept

1. Any address (e.g., `community`) submits `MsgTurnBridge{Sender: community, Enable: false}`.
2. The handler returns `nil, nil` — the transaction is accepted on-chain with `code: 0`.
3. Query the gravity `bridge_active` parameter — it remains `true`.
4. The bridge continues to process batches and accept `sendToCronos` / `sendToEthereum` operations.
5. The admin submits the same message — same result: success response, no state change, bridge still active. [1](#0-0)

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

**File:** docs/architecture/adr-009.md (L36-38)
```markdown
- Assign to each "restricted" messages in Cronos a permission (integer value) and create in Cronos module a mapping between addresses and permissions that is stored in memory. For now, there are only two messages that require permission : MsgUpdateTokenMapping and MsgTurnBridge.
- Create a msg type "MsgUpdatePermissions" that only admin can use and allow to update the address permission mapping.
- Change the logic to always check for the permission before processing the restricted messages.
```

**File:** integration_tests/test_gravity.py (L660-665)
```python
    # turn off bridge
    rsp = cli.turn_bridge("false", from_="community")
    assert rsp["code"] != 0, "should not have the permission"

    rsp = cli.turn_bridge("false", from_="validator")
    assert rsp["code"] == 0, rsp["raw_log"]
```
