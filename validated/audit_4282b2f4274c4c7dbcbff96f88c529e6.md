### Title
`MsgTurnBridge` Handler Has No Authorization Check and Is a No-Op, Permanently Breaking the Bridge Circuit Breaker — (`x/cronos/keeper/msg_server.go`)

### Summary

`TurnBridge` in the Cronos `msgServer` returns `nil, nil` with no body and no permission check. ADR-009 explicitly designates `MsgTurnBridge` as a permission-gated message requiring `CanTurnBridge`. The missing guard means any unprivileged caller can submit the message and receive a success response, while the bridge state is never mutated — permanently disabling the only on-chain circuit breaker for the gravity bridge.

---

### Finding Description

`x/cronos/keeper/msg_server.go` lines 84–87:

```go
// TurnBridge implements the grpc method
func (k msgServer) TurnBridge(goCtx context.Context, msg *types.MsgTurnBridge) (*types.MsgTurnBridgeResponse, error) {
    return nil, nil
}
``` [1](#0-0) 

Compare with `UpdateTokenMapping`, the other permission-gated message from ADR-009, which correctly calls `HasPermission`:

```go
if !k.HasPermission(ctx, msg.GetSigners(), CanChangeTokenMapping) {
    return nil, errors.Wrap(sdkerrors.ErrUnauthorized, "msg sender is not authorized")
}
``` [2](#0-1) 

ADR-009 explicitly lists `MsgTurnBridge` as one of exactly two messages that must be permission-gated:

> "For now, there are only two messages that require permission: `MsgUpdateTokenMapping` and `MsgTurnBridge`." [3](#0-2) 

The permission constants confirm `CanTurnBridge` exists and is intended to gate this message:

```go
const (
    CanChangeTokenMapping uint64 = 1 << iota // 1
    CanTurnBridge                             // 2
    All = CanChangeTokenMapping | CanTurnBridge // 3
)
``` [4](#0-3) 

Two distinct defects are present simultaneously:

1. **No authorization check** — `msg.sender` is never compared against `CanTurnBridge` permission or the admin address. Any unprivileged account can submit `MsgTurnBridge` and receive a `code: 0` success response.
2. **No state mutation** — the function body is empty (`return nil, nil`). Even a legitimately authorized caller cannot disable the bridge; the bridge-enabled flag is never written.

---

### Impact Explanation

The gravity bridge circuit breaker is the sole on-chain mechanism to halt bridge operations in an emergency (e.g., a bridge contract exploit, oracle manipulation, or mass-drain event). With `TurnBridge` being a no-op:

- **Auth bypass (High)**: The `CanTurnBridge` permission boundary — the only access control protecting this privileged operation — is completely absent. Any unprivileged address can call `MsgTurnBridge` and receive a success response, bypassing the permission system defined in ADR-009.
- **Permanent inability to halt the bridge (High)**: No on-chain path exists to disable the gravity bridge. If the bridge is exploited, operators have no recourse through the intended circuit-breaker mechanism. This constitutes a long-lived inability for the admin/governance to exercise a critical bridge authorization control.

Both map directly to the allowed High impact scope:
- *"Bypass of Cronos admin, governance authority, permission, token-mapping, bridge, block-list, or module-account authorization checks"*
- *"Permanent or long-lived inability for honest users or validators to process valid transactions, bridge/conversion flows, precompile calls, IBC transfers, or block proposals under normal network assumptions"*

---

### Likelihood Explanation

The entry point is a standard Cosmos SDK `Msg` transaction, reachable by any account with gas. No special privileges, leaked keys, or cryptographic breaks are required. The proto definition confirms `MsgTurnBridge` is a publicly routable message:

```proto
message MsgTurnBridge {
  option (cosmos.msg.v1.signer) = "sender";
  string sender = 1;
  bool   enable = 2;
}
``` [5](#0-4) 

The Cosmos SDK ante handler enforces that the transaction is signed by `msg.sender`, but it does not enforce that `msg.sender` holds `CanTurnBridge` — that check was supposed to be inside `TurnBridge` itself and is absent.

---

### Recommendation

Implement `TurnBridge` with the same pattern used by `UpdateTokenMapping`:

```go
func (k msgServer) TurnBridge(goCtx context.Context, msg *types.MsgTurnBridge) (*types.MsgTurnBridgeResponse, error) {
    ctx := sdk.UnwrapSDKContext(goCtx)
    if !k.HasPermission(ctx, msg.GetSigners(), CanTurnBridge) {
        return nil, errors.Wrap(sdkerrors.ErrUnauthorized, "msg sender is not authorized")
    }
    // write bridge-enabled state
    params := k.GetParams(ctx)
    params.EnableGravity = msg.Enable
    if err := k.SetParams(ctx, params); err != nil {
        return nil, err
    }
    return &types.MsgTurnBridgeResponse{}, nil
}
``` [6](#0-5) 

---

### Proof of Concept

1. Any unprivileged account submits:
   ```
   cronosd tx cronos turn-bridge false --from attacker --chain-id cronos_777-1
   ```
2. The transaction is accepted and returns `code: 0` — the `CanTurnBridge` permission check is never executed.
3. The bridge-enabled flag is unchanged; the bridge continues operating.
4. An authorized operator subsequently submits the same message — it also returns `code: 0` with no effect. The bridge cannot be halted through any on-chain path. [1](#0-0) [7](#0-6)

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

**File:** docs/architecture/adr-009.md (L36-38)
```markdown
- Assign to each "restricted" messages in Cronos a permission (integer value) and create in Cronos module a mapping between addresses and permissions that is stored in memory. For now, there are only two messages that require permission : MsgUpdateTokenMapping and MsgTurnBridge.
- Create a msg type "MsgUpdatePermissions" that only admin can use and allow to update the address permission mapping.
- Change the logic to always check for the permission before processing the restricted messages.
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

**File:** proto/cronos/tx.proto (L81-86)
```text
// MsgTurnBridge defines the request type
message MsgTurnBridge {
  option (cosmos.msg.v1.signer) = "sender";
  string sender                 = 1;
  bool   enable                 = 2;
}
```
