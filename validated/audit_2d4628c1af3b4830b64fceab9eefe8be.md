### Title
`TurnBridge` Keeper Implementation Is Empty — Any Unprivileged Caller Succeeds and the Bridge Can Never Be Disabled - (File: x/cronos/keeper/msg_server.go)

### Summary
The `TurnBridge` message handler in Cronos has a completely empty body. It performs no permission check and makes no state change, returning `nil, nil` unconditionally. This is the direct analog to the external report's "function can never execute its intended logic" pattern: instead of always reverting, the function always silently succeeds while doing nothing. Any unprivileged address can call `MsgTurnBridge` and receive a success response, and no authorized party can ever actually disable the gravity bridge.

### Finding Description
The `TurnBridge` gRPC handler in `x/cronos/keeper/msg_server.go` is implemented as:

```go
// TurnBridge implements the grpc method
func (k msgServer) TurnBridge(goCtx context.Context, msg *types.MsgTurnBridge) (*types.MsgTurnBridgeResponse, error) {
    return nil, nil
}
``` [1](#0-0) 

Compare this to `UpdateTokenMapping`, which correctly gates execution behind a `HasPermission` check:

```go
if !k.HasPermission(ctx, msg.GetSigners(), CanChangeTokenMapping) {
    return nil, errors.Wrap(sdkerrors.ErrUnauthorized, "msg sender is not authorized")
}
``` [2](#0-1) 

The permission system defines `CanTurnBridge` as a distinct bit-flag, and the ADR-009 design document explicitly states that `MsgTurnBridge` is one of the two restricted messages that must require permission: [3](#0-2) [4](#0-3) 

The proto definition and CLI both expose `MsgTurnBridge` as a live, callable transaction surface: [5](#0-4) [6](#0-5) 

### Impact Explanation
Two distinct High-severity impacts apply simultaneously:

1. **Authorization bypass**: Because `TurnBridge` has no permission check, any unprivileged address can submit a `MsgTurnBridge` transaction and receive a success response (`code == 0`). The `CanTurnBridge` permission and the `CronosAdmin` guard are entirely bypassed.

2. **Permanent inability to disable the bridge**: Because the function makes no state change, no one — not the admin, not governance — can ever actually disable the gravity bridge via this message. The circuit-breaker mechanism described in ADR-009 is permanently non-functional. The integration test `test_gravity_turn_bridge` calls `turn_bridge("false", from_="validator")` and then asserts that subsequent bridge operations fail — but with this empty implementation, those assertions would fail because the bridge state is never written. [7](#0-6) 

### Likelihood Explanation
The entry path is fully reachable by any unprivileged user via the standard Cosmos SDK transaction flow. The `MsgTurnBridge` message is registered in the gRPC service descriptor and the CLI. No special keys, validator access, or cryptographic assumptions are required. The bug is triggered on every call.

### Recommendation
Implement `TurnBridge` with the same pattern as `UpdateTokenMapping`:
1. Check `HasPermission(ctx, msg.GetSigners(), CanTurnBridge)` and return `ErrUnauthorized` if the check fails.
2. Write the bridge-enabled state to the keeper store (e.g., a `SetBridgeEnabled(ctx, msg.Enable)` call) so the end-blocker and other bridge logic can read it.

### Proof of Concept
1. Any address (e.g., `community`) submits `MsgTurnBridge{Sender: community, Enable: false}`.
2. The handler executes `return nil, nil` — no permission check, no state write.
3. The transaction is accepted on-chain with `code == 0`.
4. The bridge remains enabled; all subsequent bridge operations continue to succeed.
5. The admin submits the same message — same result. The bridge cannot be disabled by anyone.

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

**File:** docs/architecture/adr-009.md (L36-38)
```markdown
- Assign to each "restricted" messages in Cronos a permission (integer value) and create in Cronos module a mapping between addresses and permissions that is stored in memory. For now, there are only two messages that require permission : MsgUpdateTokenMapping and MsgTurnBridge.
- Create a msg type "MsgUpdatePermissions" that only admin can use and allow to update the address permission mapping.
- Change the logic to always check for the permission before processing the restricted messages.
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

**File:** integration_tests/test_gravity.py (L661-665)
```python
    rsp = cli.turn_bridge("false", from_="community")
    assert rsp["code"] != 0, "should not have the permission"

    rsp = cli.turn_bridge("false", from_="validator")
    assert rsp["code"] == 0, rsp["raw_log"]
```
