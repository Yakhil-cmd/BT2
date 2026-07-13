### Title
`MsgTurnBridge` Handler Is an Unguarded No-Op — Emergency Bridge Halt Permanently Broken and Permission Check Absent - (File: `x/cronos/keeper/msg_server.go`)

### Summary
The `TurnBridge` message handler in `x/cronos/keeper/msg_server.go` is a stub that immediately returns `nil, nil`. It performs no permission check and writes no state. Any unprivileged address can submit `MsgTurnBridge` and receive a success response, bypassing the `CanTurnBridge` permission gate entirely. Simultaneously, the bridge can never actually be halted — the emergency circuit-breaker designed for incident response is permanently non-functional.

### Finding Description
`MsgTurnBridge` is the protocol-level emergency stop for the Cronos bridge. ADR-009 explicitly documents it as the mechanism for "disabling the bridge module in case of emergency," and the permission system assigns `CanTurnBridge` as a distinct bit-flag for this purpose.

The actual handler implementation is:

```go
// TurnBridge implements the grpc method
func (k msgServer) TurnBridge(goCtx context.Context, msg *types.MsgTurnBridge) (*types.MsgTurnBridgeResponse, error) {
    return nil, nil
}
``` [1](#0-0) 

Compare this to the adjacent `UpdateTokenMapping` handler, which correctly gates on `HasPermission`:

```go
if !k.HasPermission(ctx, msg.GetSigners(), CanChangeTokenMapping) {
    return nil, errors.Wrap(sdkerrors.ErrUnauthorized, "msg sender is not authorized")
}
``` [2](#0-1) 

`TurnBridge` has no equivalent guard. The `CanTurnBridge` constant is defined and the permission infrastructure exists: [3](#0-2) 

But it is never consulted in the handler. The proto definition confirms `MsgTurnBridge` is a live, registered message type reachable by any signer: [4](#0-3) 

### Impact Explanation
Two distinct High-severity impacts apply:

1. **Authorization bypass**: Any unprivileged address can submit `MsgTurnBridge` and receive a `200 OK` (nil error). The `CanTurnBridge` permission check — the only guard protecting this privileged operation — is completely absent. This directly satisfies: *"Bypass of Cronos admin, governance authority, permission, token-mapping, bridge, block-list, or module-account authorization checks."*

2. **Permanent inability to halt the bridge**: Because the handler writes no state, even a legitimately permissioned admin calling `MsgTurnBridge(enable=false)` cannot stop the bridge. In an active exploit scenario, the bridge continues processing outbound transfers indefinitely. This satisfies: *"Permanent or long-lived inability for honest users or validators to process valid transactions, bridge/conversion flows."*

### Likelihood Explanation
The entry path is trivially reachable — `MsgTurnBridge` is a standard Cosmos SDK message registered in the module's codec and gRPC server, callable by any address with gas. No special privileges, leaked keys, or cryptographic assumptions are required. The stub has been present since the permission system was introduced (ADR-009), meaning it has never functioned correctly. [5](#0-4) 

### Recommendation
Implement `TurnBridge` with the same pattern used by `UpdateTokenMapping`:

```go
func (k msgServer) TurnBridge(goCtx context.Context, msg *types.MsgTurnBridge) (*types.MsgTurnBridgeResponse, error) {
    ctx := sdk.UnwrapSDKContext(goCtx)
    if !k.HasPermission(ctx, msg.GetSigners(), CanTurnBridge) {
        return nil, errors.Wrap(sdkerrors.ErrUnauthorized, "msg sender is not authorized")
    }
    // persist bridge enable/disable state and enforce in EVM hooks / IBC handlers
    if err := k.SetBridgeActive(ctx, msg.Enable); err != nil {
        return nil, err
    }
    return &types.MsgTurnBridgeResponse{}, nil
}
```

The bridge-active flag must then be checked at every outbound bridge entry point (EVM hooks, IBC transfer handlers) so that `enable=false` actually halts fund movement.

### Proof of Concept
1. Any address `attacker` submits `MsgTurnBridge{Sender: attacker, Enable: false}`.
2. The handler returns `nil, nil` — the transaction is accepted on-chain with no error.
3. No state is written; the bridge continues operating normally.
4. A legitimately permissioned admin submitting the same message also gets `nil, nil` — the bridge cannot be halted by anyone.
5. During an active exploit draining bridge funds, the emergency stop is permanently unavailable. [1](#0-0) [6](#0-5)

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

**File:** x/cronos/types/codec.go (L1-5)
```go
package types

import (
	"github.com/cosmos/cosmos-sdk/codec"
	cdctypes "github.com/cosmos/cosmos-sdk/codec/types"
```
