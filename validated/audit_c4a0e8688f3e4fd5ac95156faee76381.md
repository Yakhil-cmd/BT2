### Title
`MsgTurnBridge` Handler is a No-Op, Bypassing Authorization and Permanently Disabling Bridge Control — (File: x/cronos/keeper/msg_server.go)

---

### Summary

The `TurnBridge` message handler in `x/cronos/keeper/msg_server.go` is implemented as a complete no-op (`return nil, nil`). It never performs the `CanTurnBridge` permission check and never modifies any bridge state. Any unprivileged user can submit `MsgTurnBridge` and receive a success response (code 0), while the bridge state remains permanently unchanged and uncontrollable.

---

### Finding Description

`msgServer.TurnBridge` at lines 84–87 of `x/cronos/keeper/msg_server.go` is:

```go
func (k msgServer) TurnBridge(goCtx context.Context, msg *types.MsgTurnBridge) (*types.MsgTurnBridgeResponse, error) {
    return nil, nil
}
``` [1](#0-0) 

This is a complete no-op. Contrast with `UpdateTokenMapping`, which correctly gates on `HasPermission`:

```go
if !k.HasPermission(ctx, msg.GetSigners(), CanChangeTokenMapping) {
    return nil, errors.Wrap(sdkerrors.ErrUnauthorized, "msg sender is not authorized")
}
``` [2](#0-1) 

The `CanTurnBridge` permission constant is defined and the `HasPermission` machinery exists: [3](#0-2) 

`HasPermission` checks both the `CronosAdmin` param and per-address permission bits: [4](#0-3) 

Neither check is ever reached for `TurnBridge`. The `BlockAddressesDecorator` ante handler only enforces authorization for `MsgStoreBlockList`, not `MsgTurnBridge`: [5](#0-4) 

The proto surface confirms `TurnBridge` is a live, signed, on-chain message type: [6](#0-5) 

---

### Impact Explanation

Two distinct High impacts apply simultaneously:

**1. Bypass of authorization check (High)**
Any unprivileged account can submit `MsgTurnBridge` and receive a success response. The `CanTurnBridge` permission bit is never evaluated. This directly satisfies: *"Bypass of Cronos admin, governance authority, permission, token-mapping, bridge, block-list, or module-account authorization checks."*

**2. Permanent inability to stop the bridge (High)**
Because the handler is a no-op, the bridge enable/disable state is never written to the KV store. The admin and any permissioned operator are permanently unable to halt the gravity bridge — including during an active exploit. This satisfies: *"Permanent or long-lived inability for honest users or validators to process valid transactions, bridge/conversion flows … under normal network assumptions."*

---

### Likelihood Explanation

`MsgTurnBridge` is a production-registered Cosmos SDK message with a CLI command (`CmdTurnBridge`), a proto definition, and integration tests that explicitly expect it to enforce permissions. The no-op body is not guarded by a feature flag or build tag. Any account with gas can submit it today and receive code 0. [7](#0-6) 

---

### Recommendation

Implement `TurnBridge` to:
1. Call `k.HasPermission(ctx, msg.GetSigners(), CanTurnBridge)` and return `ErrUnauthorized` on failure.
2. Persist the `Enable` flag to the KV store (analogous to how `SetParams` is used in `UpdateParams`).
3. Propagate the state change to the gravity bridge module so that bridge operations respect the flag.

---

### Proof of Concept

1. Attacker (any address, no special permissions) broadcasts:
   ```
   MsgTurnBridge { Sender: <attacker_addr>, Enable: false }
   ```
2. `msgServer.TurnBridge` returns `nil, nil` — Cosmos SDK emits code 0 (success).
3. No permission check is performed; no state is written.
4. Admin subsequently broadcasts the same message with `Enable: false` to halt an ongoing bridge exploit — also returns code 0 with no effect.
5. The gravity bridge continues processing outbound transfers indefinitely; the circuit-breaker intended by `TurnBridge` is permanently inoperative.

The integration test at `integration_tests/test_gravity.py` explicitly asserts that an unprivileged `community` account calling `turn_bridge` must receive `code != 0` — a contract the current no-op implementation violates for every caller.

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

**File:** app/block_address.go (L74-82)
```go
		admin := bad.getParams(ctx).CronosAdmin
		for _, msg := range tx.GetMsgs() {
			if blocklistMsg, ok := msg.(*types.MsgStoreBlockList); ok {
				if admin != blocklistMsg.From {
					return ctx, errors.Wrap(sdkerrors.ErrUnauthorized, "msg sender is not authorized")
				}
			}
		}
	}
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
