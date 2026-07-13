### Title
`TurnBridge` Missing Permission Check and Unimplemented Logic Allows Any Unprivileged User to Call Bridge Toggle While Permanently Preventing Bridge Disablement — (`x/cronos/keeper/msg_server.go`)

---

### Summary

The `msgServer.TurnBridge` handler in `x/cronos/keeper/msg_server.go` is completely unimplemented: it returns `nil, nil` unconditionally, performing no permission check and no state mutation. Any unprivileged account can submit `MsgTurnBridge` and receive a success response, bypassing the `CanTurnBridge` permission gate that is explicitly defined in the permissions system. Simultaneously, no authorized party — including the Cronos admin — can ever actually disable the bridge, because the function that is supposed to update the bridge-enabled state is a no-op.

---

### Finding Description

`UpdateTokenMapping` correctly gates its execution behind `HasPermission(ctx, msg.GetSigners(), CanChangeTokenMapping)`:

```go
// x/cronos/keeper/msg_server.go:72-75
if !k.HasPermission(ctx, msg.GetSigners(), CanChangeTokenMapping) {
    return nil, errors.Wrap(sdkerrors.ErrUnauthorized, "msg sender is not authorized")
}
```

The sibling handler `TurnBridge`, which is supposed to enable or disable the gravity bridge and is protected by the `CanTurnBridge` permission constant defined in `permissions.go`, contains no such check and no implementation at all:

```go
// x/cronos/keeper/msg_server.go:84-87
func (k msgServer) TurnBridge(goCtx context.Context, msg *types.MsgTurnBridge) (*types.MsgTurnBridgeResponse, error) {
    return nil, nil
}
```

The permissions system explicitly defines `CanTurnBridge` as a distinct, non-zero permission bit:

```go
// x/cronos/keeper/permissions.go:14-16
const (
    CanChangeTokenMapping uint64 = 1 << iota // 1
    CanTurnBridge                             // 2
    All = CanChangeTokenMapping | CanTurnBridge // 3
)
```

The integration test in `test_gravity.py` confirms the intended contract: a `community` (unprivileged) sender calling `turn_bridge("false")` is expected to fail with a non-zero code, while a `validator` (permissioned) sender is expected to succeed. The live implementation violates both halves of this invariant: the unprivileged call succeeds (returns `nil, nil`), and the permissioned call also silently succeeds without changing any state.

**Attacker path:**

1. Any account submits `MsgTurnBridge{Sender: attacker, Enable: false}` via the gRPC/Cosmos tx endpoint.
2. The handler returns `nil, nil` — the transaction is accepted on-chain with a success code.
3. No permission check is evaluated; no bridge-enabled parameter is written.
4. The bridge remains enabled regardless of what any authorized party submits.

---

### Impact Explanation

**Auth bypass (High):** The `CanTurnBridge` permission gate is entirely absent. Any unprivileged account can call `MsgTurnBridge` and receive a success response, bypassing the authorization boundary that the permissions system is designed to enforce.

**Permanent inability to halt the bridge (High):** Because the function is a no-op, the bridge-enabled state can never be set to `false` by anyone. During an active exploit, upgrade, or critical bug scenario — the exact conditions under which the bridge is intended to be disabled — the admin has no functional mechanism to halt bridge operations. EVM hook handlers (`SendToIbcHandler`, `SendToEvmChainHandler`) that process `__CronosSendToIbc` and `__CronosSendToEvmChain` events will continue to execute IBC transfers and gravity bridge outflows regardless of any `TurnBridge` call.

This maps directly to:
- **High: Bypass of Cronos admin, governance authority, permission, token-mapping, bridge, block-list, or module-account authorization checks**
- **High: Permanent or long-lived inability for honest users or validators to process valid transactions, bridge/conversion flows, precompile calls, IBC transfers, or block proposals under normal network assumptions**

---

### Likelihood Explanation

The entry point is a standard Cosmos SDK message handler reachable by any account with a valid bech32 address and sufficient gas. No special privileges, leaked keys, or cryptographic assumptions are required. The transaction will be accepted by any node and included in a block.

---

### Recommendation

Implement `TurnBridge` with the same pattern used by `UpdateTokenMapping`:

```go
func (k msgServer) TurnBridge(goCtx context.Context, msg *types.MsgTurnBridge) (*types.MsgTurnBridgeResponse, error) {
    ctx := sdk.UnwrapSDKContext(goCtx)

    if !k.HasPermission(ctx, msg.GetSigners(), CanTurnBridge) {
        return nil, errors.Wrap(sdkerrors.ErrUnauthorized, "msg sender is not authorized")
    }

    params := k.GetParams(ctx)
    params.EnableGravity = msg.Enable  // or whichever field controls bridge state
    if err := k.SetParams(ctx, params); err != nil {
        return nil, err
    }

    return &types.MsgTurnBridgeResponse{}, nil
}
```

Additionally, verify that the EVM hook handlers (`SendToIbcHandler`, `SendToEvmChainHandler`, `CancelSendToEvmChainHandler`) read and enforce the bridge-enabled parameter before processing any outbound transfer event.

---

### Proof of Concept

```
# Any unprivileged account
cronosd tx cronos turn-bridge false \
  --from attacker \
  --chain-id cronostestnet_338-3 \
  -y

# Expected (per test_gravity.py): code != 0 (unauthorized)
# Actual: code == 0, bridge state unchanged, no permission evaluated
```

The transaction is accepted on-chain. The bridge-enabled state is not written. A subsequent call by the legitimate admin with `enable=false` also silently succeeds without effect, leaving the bridge permanently active and unhalted. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3)

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
