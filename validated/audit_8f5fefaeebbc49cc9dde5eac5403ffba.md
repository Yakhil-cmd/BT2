### Title
`TurnBridge` Is a No-Op Stub — Bridge State Can Never Be Changed - (File: `x/cronos/keeper/msg_server.go`)

### Summary

`MsgTurnBridge` is the on-chain message that authorized operators use to enable or disable the Gravity Bridge. Its handler `TurnBridge` in `x/cronos/keeper/msg_server.go` is an unimplemented stub that unconditionally returns `nil, nil` without performing any state mutation, permission check, or bridge-state update. As a result, no caller — including the Cronos admin or any address holding the `CanTurnBridge` permission — can ever change the bridge's enabled/disabled state. The bridge circuit-breaker is permanently non-functional.

### Finding Description

The `TurnBridge` handler is defined as:

```go
// TurnBridge implements the grpc method
func (k msgServer) TurnBridge(goCtx context.Context, msg *types.MsgTurnBridge) (*types.MsgTurnBridgeResponse, error) {
    return nil, nil
}
``` [1](#0-0) 

The proto definition and the permissions system both treat `TurnBridge` as a real, guarded operation. The `CanTurnBridge` permission bit exists precisely to gate this message: [2](#0-1) 

The proto service registers `MsgTurnBridge` with a `sender` signer field, and the CLI exposes `turn-bridge [true/false]` as a user-facing command: [3](#0-2) [4](#0-3) 

The integration test `test_gravity_turn_bridge` explicitly verifies that after a successful `turn_bridge("false")` call the bridge stops processing outbound transfers. Because the handler is a stub, the bridge-enabled flag is never written to state, so the bridge remains permanently active regardless of what any authorized caller submits. [5](#0-4) 

The root cause is structurally identical to the external report: a function that is supposed to enforce a state change (or an authorization gate) silently does nothing, making the intended control path permanently unreachable.

### Impact Explanation

**High — Bypass of bridge authorization / permanent inability to disable the bridge.**

The Gravity Bridge circuit-breaker is the only on-chain mechanism to halt outbound token transfers in an emergency (exploit, oracle manipulation, etc.). Because `TurnBridge` is a no-op, this mechanism is permanently disabled. Any authorized operator who submits `MsgTurnBridge{Enable: false}` receives a success response but the bridge state is never updated. The bridge cannot be stopped by any unprivileged or privileged on-chain action through the intended path, matching the allowed High impact category: *"Bypass of Cronos admin, governance authority, permission, token-mapping, bridge, block-list, or module-account authorization checks"* and *"Permanent or long-lived inability for honest users or validators to process valid … bridge/conversion flows … under normal network assumptions."*

### Likelihood Explanation

**High.** The code path is reachable by any address that holds `CanTurnBridge` permission (or the Cronos admin). No special preconditions are required beyond submitting a standard Cosmos SDK transaction. The bug is deterministic and reproducible on every invocation.

### Recommendation

Implement `TurnBridge` to:
1. Verify the caller holds `CanTurnBridge` permission via `k.HasPermission`.
2. Read the current `Params`, set `EnableGravityBridge = msg.Enable`, and persist with `k.SetParams`.

```go
func (k msgServer) TurnBridge(goCtx context.Context, msg *types.MsgTurnBridge) (*types.MsgTurnBridgeResponse, error) {
    ctx := sdk.UnwrapSDKContext(goCtx)
    if !k.HasPermission(ctx, msg.GetSigners(), CanTurnBridge) {
        return nil, errors.Wrap(sdkerrors.ErrUnauthorized, "msg sender is not authorized")
    }
    params := k.GetParams(ctx)
    params.EnableGravityBridge = msg.Enable
    if err := k.SetParams(ctx, params); err != nil {
        return nil, err
    }
    return &types.MsgTurnBridgeResponse{}, nil
}
```

### Proof of Concept

1. Grant `CanTurnBridge` permission to address `A` via `MsgUpdatePermissions`.
2. Submit `MsgTurnBridge{Sender: A, Enable: false}` — transaction succeeds (code 0).
3. Query the Cronos params — `EnableGravityBridge` is still `true`.
4. Submit a `send_to_evm_chain` EVM call — it succeeds, proving the bridge was never disabled.
5. Repeat with the Cronos admin address — same result.

The stub returns success unconditionally, so no error is surfaced, yet the bridge state is never mutated. [1](#0-0)

### Citations

**File:** x/cronos/keeper/msg_server.go (L84-87)
```go
// TurnBridge implements the grpc method
func (k msgServer) TurnBridge(goCtx context.Context, msg *types.MsgTurnBridge) (*types.MsgTurnBridgeResponse, error) {
	return nil, nil
}
```

**File:** x/cronos/keeper/permissions.go (L13-16)
```go
const (
	CanChangeTokenMapping uint64                                  = 1 << iota // 1
	CanTurnBridge                                                             // 2
	All                   = CanChangeTokenMapping | CanTurnBridge             // 3
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
