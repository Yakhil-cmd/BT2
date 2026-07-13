### Title
`MsgTurnBridge` Handler Is a No-Op Stub — Permission Check Bypassed and Bridge Circuit Breaker Permanently Non-Functional - (File: x/cronos/keeper/msg_server.go)

### Summary
The `TurnBridge` message handler, which is the designated circuit breaker for the Gravity Bridge, is implemented as a stub that unconditionally returns `nil, nil`. It performs no permission check and makes no state change. Any unprivileged address can call it and receive a success response, bypassing the `CanTurnBridge` permission gate entirely. Simultaneously, the bridge can never actually be halted via this message path, making the emergency circuit breaker permanently non-functional.

### Finding Description
The `MsgTurnBridge` message is proto-defined and registered as a live RPC endpoint. The permission system defines `CanTurnBridge` as a distinct bit-flag permission, and ADR-009 explicitly states that `MsgTurnBridge` is one of the two messages that must be restricted to permissioned addresses. The integration test `test_gravity_turn_bridge` asserts that an unpermissioned sender (`community`) must receive a non-zero error code.

However, the actual server-side handler is:

```go
// TurnBridge implements the grpc method
func (k msgServer) TurnBridge(goCtx context.Context, msg *types.MsgTurnBridge) (*types.MsgTurnBridgeResponse, error) {
    return nil, nil
}
``` [1](#0-0) 

This stub:
1. Never calls `k.HasPermission(ctx, msg.GetSigners(), CanTurnBridge)` — the check that `UpdateTokenMapping` correctly performs.
2. Never reads or writes any bridge-active state.
3. Returns `nil` error for every caller, including completely unprivileged addresses.

The permission constants and check logic exist and are correct in isolation: [2](#0-1) [3](#0-2) 

`UpdateTokenMapping` correctly enforces its permission: [4](#0-3) 

But `TurnBridge` has no equivalent guard. The proto surface is fully reachable: [5](#0-4) 

### Impact Explanation
Two distinct impacts apply:

**High — Bypass of Cronos permission/authorization check**: Any unprivileged address can submit `MsgTurnBridge` and receive a `code: 0` success response. The `CanTurnBridge` permission bit, the admin check, and the entire permission system are silently bypassed for this message. The integration test expectation that `community` receives a non-zero code is violated.

**High — Permanent inability to halt the bridge**: The Gravity Bridge circuit breaker is permanently non-functional. In an emergency (e.g., a bridge exploit in progress), no permissioned actor can halt bridge processing via `MsgTurnBridge` because the handler never updates any state. The bridge cannot be turned off through this message path under any circumstances.

### Likelihood Explanation
The message is registered, the CLI command `CmdTurnBridge` is wired up, and the endpoint is reachable by any on-chain transaction sender. The stub is not gated behind any feature flag. Any user who submits the transaction will observe a success response regardless of their permission level. [6](#0-5) 

### Recommendation
Implement `TurnBridge` analogously to `UpdateTokenMapping`:
1. Unwrap the SDK context.
2. Call `k.HasPermission(ctx, msg.GetSigners(), CanTurnBridge)` and return `ErrUnauthorized` on failure.
3. Persist the bridge-active state (e.g., update the `bridge_active` gravity parameter or a dedicated cronos module param) based on `msg.Enable`.

### Proof of Concept
1. Any address (no `CanTurnBridge` permission, not the `CronosAdmin`) submits:
   ```
   MsgTurnBridge{ Sender: <unprivileged_address>, Enable: false }
   ```
2. The handler at `msg_server.go:85-87` executes `return nil, nil`.
3. The transaction is included in a block with `code: 0` (success).
4. No bridge state is changed; the bridge continues operating.
5. A permissioned actor subsequently submits `MsgTurnBridge{ Enable: false }` in a genuine emergency — also returns success, also changes no state. The bridge cannot be halted. [1](#0-0)

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

**File:** x/cronos/keeper/permissions.go (L31-48)
```go
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
