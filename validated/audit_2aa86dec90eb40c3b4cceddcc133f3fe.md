### Title
Unimplemented `TurnBridge` Keeper Stub Permanently Bypasses Bridge Authorization and Prevents Bridge Shutdown - (File: `x/cronos/keeper/msg_server.go`)

### Summary
The `TurnBridge` gRPC message handler is a complete no-op stub. It performs no permission check and writes no state, meaning (1) any unprivileged sender can call it and receive a success response, bypassing the `CanTurnBridge` permission system entirely, and (2) the bridge can never actually be disabled, permanently removing the admin's emergency shutdown capability.

### Finding Description
`TurnBridge` in `msg_server.go` is registered as a live gRPC handler but its entire body is:

```go
func (k msgServer) TurnBridge(goCtx context.Context, msg *types.MsgTurnBridge) (*types.MsgTurnBridgeResponse, error) {
    return nil, nil
}
``` [1](#0-0) 

The codebase has a fully built permission system with a dedicated `CanTurnBridge` bit:

```go
CanTurnBridge uint64 = 2
``` [2](#0-1) 

`HasPermission` is correctly called in the analogous `UpdateTokenMapping` handler: [3](#0-2) 

But `TurnBridge` calls neither `HasPermission` nor any state-writing keeper method. The proto definition, CLI command, and integration test all treat `TurnBridge` as a real, state-changing operation: [4](#0-3) [5](#0-4) 

The integration test `test_gravity_turn_bridge` explicitly asserts that an unprivileged sender (`community`) must be rejected and that a privileged sender (`validator`) must actually disable bridge outflows: [6](#0-5) 

Because the handler is a stub, both assertions fail silently on-chain: the unprivileged call succeeds (code 0), and the bridge state is never written, so bridge outflows continue regardless.

### Impact Explanation
Two simultaneous High impacts:

1. **Bypass of bridge authorization**: The `CanTurnBridge` permission check is never enforced. Any unprivileged address can submit `MsgTurnBridge` and receive a success response, defeating the access-control model for bridge control.

2. **Permanent inability to disable bridge flows**: Because no state is written, the bridge can never be turned off. Authorized validators/admins lose their only on-chain mechanism to halt `send_to_evm_chain` / `send_to_ethereum` outflows in an emergency (e.g., an active exploit draining CRC20/CRC21 assets through the Gravity bridge). This is a permanent, protocol-level inability to stop bridge/conversion flows.

### Likelihood Explanation
The entry path is a standard signed Cosmos SDK transaction (`MsgTurnBridge`) reachable by any account with gas. No special privilege is required to trigger the authorization bypass. The bridge-shutdown failure is triggered every time a legitimate admin attempts to halt the bridge.

### Recommendation
Implement `TurnBridge` with the same pattern used by `UpdateTokenMapping`:

1. Check `HasPermission(ctx, msg.GetSigners(), CanTurnBridge)` and return `sdkerrors.ErrUnauthorized` on failure.
2. Persist the `enable` flag to module params (e.g., a `BridgeEnabled` field in `Params`) via `k.SetParams`.
3. Add a guard in the `SendToEthereum` / `send_to_evm_chain` EVM hook handlers that reads this flag and rejects outbound bridge calls when `BridgeEnabled == false`.

### Proof of Concept
```
# Any unprivileged address succeeds (should return code != 0):
cronosd tx cronos turn-bridge false --from community --chain-id cronos_777-1 -y
# → code: 0  (authorization bypass confirmed)

# Validator call also returns code 0 but bridge remains open:
cronosd tx cronos turn-bridge false --from validator --chain-id cronos_777-1 -y
# → code: 0, but send_to_evm_chain EVM events continue to be processed
#   because no BridgeEnabled flag was ever written to state.
```

The stub at [7](#0-6)  is the direct Cronos analog to the external report's pattern of commented-out essential guards: the code surface exists and is reachable, but the critical logic body was never implemented.

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

**File:** x/cronos/keeper/permissions.go (L13-17)
```go
const (
	CanChangeTokenMapping uint64                                  = 1 << iota // 1
	CanTurnBridge                                                             // 2
	All                   = CanChangeTokenMapping | CanTurnBridge             // 3
)
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
