### Title
`MsgTurnBridge` Handler Is a No-Op — Missing Permission Check and State Change - (File: `x/cronos/keeper/msg_server.go`)

### Summary

The `TurnBridge` message handler in `x/cronos/keeper/msg_server.go` is completely unimplemented. It performs no permission check and makes no state change, returning `nil, nil` unconditionally. Any unprivileged user can call `MsgTurnBridge` and receive a success response, while the bridge circuit breaker is permanently non-functional.

### Finding Description

The `TurnBridge` gRPC handler is registered in the Cronos message server and is reachable by any on-chain sender via a standard Cosmos SDK transaction. The implementation is:

```go
// TurnBridge implements the grpc method
func (k msgServer) TurnBridge(goCtx context.Context, msg *types.MsgTurnBridge) (*types.MsgTurnBridgeResponse, error) {
    return nil, nil
}
``` [1](#0-0) 

The permission system defines `CanTurnBridge` as a distinct privilege bit, and `HasPermission` is the intended guard: [2](#0-1) 

`UpdateTokenMapping` — the analogous restricted handler — correctly enforces this pattern: [3](#0-2) 

`TurnBridge` does neither. The proto definition and CLI command are fully wired: [4](#0-3) [5](#0-4) 

### Impact Explanation

Two distinct impacts:

1. **Authorization bypass (High):** Any unprivileged address can submit `MsgTurnBridge` and receive a success response. The `CanTurnBridge` permission check — which ADR-009 explicitly designates as a restricted operation — is never enforced.

2. **Permanent bridge circuit-breaker failure (High):** Because the handler makes no state change, the bridge can never be disabled. The integration test `test_gravity_turn_bridge` confirms the expected behavior is that `send_to_evm_chain` fails after the bridge is turned off. That invariant is permanently broken. [6](#0-5) 

### Likelihood Explanation

The entry path is a standard Cosmos SDK transaction (`/cronos.Msg/TurnBridge`), reachable by any account with gas. No special privileges, leaked keys, or cryptographic breaks are required. The handler silently succeeds, so the failure is invisible to callers.

### Recommendation

Implement `TurnBridge` with:
1. A `HasPermission(ctx, msg.GetSigners(), CanTurnBridge)` check, mirroring `UpdateTokenMapping`.
2. An actual state write that persists the bridge enabled/disabled flag (e.g., a dedicated store key or a params field).
3. All downstream bridge-flow handlers (EVM hooks, IBC middleware) must read and enforce that flag.

### Proof of Concept

```
# Any unprivileged address can call this and receive code=0
cronosd tx cronos turn-bridge false --from=<any_address> -y

# Expected: error "msg sender is not authorized"
# Actual:   success (nil, nil returned by handler)
```

The `CanTurnBridge` permission constant exists and is queryable but is never checked at the execution boundary: [7](#0-6) [1](#0-0)

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

**File:** x/cronos/keeper/grpc_query.go (L123-144)
```go
// Permissions returns the permissions of a specific account
func (k Keeper) Permissions(goCtx context.Context, req *types.QueryPermissionsRequest) (*types.QueryPermissionsResponse, error) {
	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "empty request")
	}
	ctx := sdk.UnwrapSDKContext(goCtx)
	acc, err := sdk.AccAddressFromBech32(req.Address)
	if err != nil {
		return nil, err
	}
	admin := k.GetParams(ctx).CronosAdmin
	if admin == acc.String() {
		return &types.QueryPermissionsResponse{
			CanChangeTokenMapping: true,
			CanTurnBridge:         true,
		}, nil
	}
	permissions := k.GetPermissions(ctx, acc)
	return &types.QueryPermissionsResponse{
		CanChangeTokenMapping: CanChangeTokenMapping == (permissions & CanChangeTokenMapping),
		CanTurnBridge:         CanTurnBridge == (permissions & CanTurnBridge),
	}, nil
```
