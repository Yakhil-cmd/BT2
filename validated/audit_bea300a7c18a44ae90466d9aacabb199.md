### Title
`MsgTurnBridge` Is a No-Op That Bypasses the `CanTurnBridge` Permission Check and Permanently Disables the Bridge Circuit Breaker - (File: `x/cronos/keeper/msg_server.go`)

### Summary
The `TurnBridge` message handler in `x/cronos/keeper/msg_server.go` is implemented as a bare `return nil, nil` with no permission check and no state mutation. Any unprivileged address can submit `MsgTurnBridge` and receive a success response, bypassing the `CanTurnBridge` permission guard that is correctly enforced on the analogous `UpdateTokenMapping` handler. Simultaneously, the bridge can never actually be disabled: the emergency circuit breaker is permanently broken.

### Finding Description
The `TurnBridge` gRPC handler is:

```go
// TurnBridge implements the grpc method
func (k msgServer) TurnBridge(goCtx context.Context, msg *types.MsgTurnBridge) (*types.MsgTurnBridgeResponse, error) {
    return nil, nil
}
``` [1](#0-0) 

Compare with the correctly-guarded sibling handler:

```go
if !k.HasPermission(ctx, msg.GetSigners(), CanChangeTokenMapping) {
    return nil, errors.Wrap(sdkerrors.ErrUnauthorized, "msg sender is not authorized")
}
``` [2](#0-1) 

The permission constants are defined as:

```go
const (
    CanChangeTokenMapping uint64 = 1 << iota // 1
    CanTurnBridge                             // 2
    All = CanChangeTokenMapping | CanTurnBridge // 3
)
``` [3](#0-2) 

`TurnBridge` never calls `HasPermission` and never writes any state. The proto surface, CLI command, and integration-test fixture all exist and are reachable by any signer: [4](#0-3) [5](#0-4) 

The integration test explicitly asserts that an unprivileged caller must be rejected:

```python
rsp = cli.turn_bridge("false", from_="community")
assert rsp["code"] != 0, "should not have the permission"
``` [6](#0-5) 

Because the handler returns `nil, nil`, this assertion fails: the community address receives code 0 (success) without holding `CanTurnBridge`.

### Impact Explanation
Two distinct impacts arise from the same root cause:

1. **Permission bypass (High):** Any unprivileged address can submit `MsgTurnBridge` and receive a successful on-chain response, bypassing the `CanTurnBridge` authorization check that the permission system is designed to enforce. This directly satisfies the allowed impact: *"Bypass of Cronos admin, governance authority, permission … authorization checks."*

2. **Bridge circuit breaker permanently broken (High):** Because the handler writes no state, the bridge can never be disabled regardless of who calls it. ADR-009 explicitly describes `MsgTurnBridge` as the emergency circuit breaker for the Gravity Bridge module. [7](#0-6) 
   If a bridge-level exploit is active (e.g., the malicious-supply scenario tested in `test_gravity_detect_malicious_supply`), operators have no on-chain mechanism to halt bridge operations. This satisfies: *"High: Permanent or long-lived inability for honest users or validators to process valid … bridge/conversion flows … under normal network assumptions"* — specifically the inability to stop a broken bridge flow.

### Likelihood Explanation
The entry path is fully unprivileged: any Cosmos address can broadcast a `MsgTurnBridge` transaction via the standard CLI or gRPC. No special keys, validator access, or governance proposal is required. The bug is present in the production keeper and is reachable on every block.

### Recommendation
Implement `TurnBridge` with the same pattern used by `UpdateTokenMapping`:

```go
func (k msgServer) TurnBridge(goCtx context.Context, msg *types.MsgTurnBridge) (*types.MsgTurnBridgeResponse, error) {
    ctx := sdk.UnwrapSDKContext(goCtx)
    if !k.HasPermission(ctx, msg.GetSigners(), CanTurnBridge) {
        return nil, errors.Wrap(sdkerrors.ErrUnauthorized, "msg sender is not authorized")
    }
    // persist bridge-enabled flag and propagate to gravity params
    ...
    return &types.MsgTurnBridgeResponse{}, nil
}
```

The handler must (a) enforce `CanTurnBridge`, (b) persist the enabled/disabled flag to the gravity module's `bridge_active` parameter or an equivalent store key, and (c) be covered by a unit test that verifies both the permission rejection and the state change.

### Proof of Concept
1. Start a Cronos node with the Gravity Bridge enabled.
2. From any address that does **not** hold `CanTurnBridge` permission (e.g., `community`):
   ```
   cronosd tx cronos turn-bridge false --from community -y
   ```
3. Observe `code: 0` in the response — the transaction succeeds despite the caller lacking the required permission.
4. Query the gravity bridge parameters; `bridge_active` remains `true` — the bridge is not disabled.
5. Repeat from the privileged `validator` address; the result is identical: `code: 0`, bridge still active.

The no-op implementation means neither the permission guard nor the state transition is ever executed, confirming both the authorization bypass and the permanently broken circuit breaker.

### Citations

**File:** x/cronos/keeper/msg_server.go (L73-75)
```go
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

**File:** proto/cronos/tx.proto (L29-30)
```text
  // TurnBridge defines a method to disable or enable the gravity bridge
  rpc TurnBridge(MsgTurnBridge) returns (MsgTurnBridgeResponse);
```

**File:** integration_tests/test_gravity.py (L661-662)
```python
    rsp = cli.turn_bridge("false", from_="community")
    assert rsp["code"] != 0, "should not have the permission"
```

**File:** docs/architecture/adr-009.md (L36-38)
```markdown
- Assign to each "restricted" messages in Cronos a permission (integer value) and create in Cronos module a mapping between addresses and permissions that is stored in memory. For now, there are only two messages that require permission : MsgUpdateTokenMapping and MsgTurnBridge.
- Create a msg type "MsgUpdatePermissions" that only admin can use and allow to update the address permission mapping.
- Change the logic to always check for the permission before processing the restricted messages.
```
