### Title
`MsgTurnBridge` Handler Is a No-Op: Missing Permission Check and Missing State Mutation — (`File: x/cronos/keeper/msg_server.go`)

---

### Summary

The `TurnBridge` gRPC message handler in `x/cronos/keeper/msg_server.go` is implemented as a bare `return nil, nil`. It performs no authorization check and mutates no state. This produces two simultaneous failures: (1) any unprivileged address can submit `MsgTurnBridge` and receive a success response, bypassing the `CanTurnBridge` permission gate entirely; and (2) even a legitimately authorized address cannot disable the Gravity Bridge because the handler never writes the bridge-active flag.

---

### Finding Description

`MsgTurnBridge` is one of the two messages that ADR-009 explicitly designates as requiring the `CanTurnBridge` permission bit. The parallel handler `UpdateTokenMapping` correctly enforces this:

```go
// UpdateTokenMapping — correct
if !k.HasPermission(ctx, msg.GetSigners(), CanChangeTokenMapping) {
    return nil, errors.Wrap(sdkerrors.ErrUnauthorized, "msg sender is not authorized")
}
``` [1](#0-0) 

The `TurnBridge` handler, however, is:

```go
// TurnBridge implements the grpc method
func (k msgServer) TurnBridge(goCtx context.Context, msg *types.MsgTurnBridge) (*types.MsgTurnBridgeResponse, error) {
    return nil, nil
}
``` [2](#0-1) 

The permission constants are defined and `CanTurnBridge` is explicitly reserved for this message:

```go
const (
    CanChangeTokenMapping uint64 = 1 << iota // 1
    CanTurnBridge                             // 2
    All = CanChangeTokenMapping | CanTurnBridge // 3
)
``` [3](#0-2) 

The proto service definition confirms `TurnBridge` is a live, registered RPC endpoint reachable by any signer: [4](#0-3) 

The integration test explicitly asserts that an unauthorized sender must receive a non-zero error code, and that after a successful `turn_bridge("false")` the bridge is actually disabled: [5](#0-4) 

Both assertions are violated by the current implementation.

---

### Impact Explanation

**Dual impact, both High:**

1. **Authorization bypass**: Any unprivileged address can broadcast `MsgTurnBridge` with any `enable` value and receive a `code=0` success response. The `CanTurnBridge` permission gate — the only mechanism protecting this privileged operation — is never evaluated.

2. **Permanent inability to disable the bridge**: The Gravity Bridge emergency circuit-breaker is completely non-functional. Even the admin or a permissioned address cannot disable the bridge because the handler never writes the `bridge_active` flag. During a live exploit or bridge compromise, the authorized parties have no on-chain mechanism to halt asset flows.

Both map directly to the allowed High impact category: *"Bypass of Cronos admin, governance authority, permission, token-mapping, bridge, block-list, or module-account authorization checks"* and *"Permanent or long-lived inability for honest users or validators to process valid transactions, bridge/conversion flows."*

---

### Likelihood Explanation

The entry path is a standard signed Cosmos SDK transaction — no special privileges, no leaked keys, no cryptographic assumptions. Any address with gas can submit `MsgTurnBridge`. The handler is registered in the live gRPC service. Likelihood is **High**.

---

### Recommendation

Implement `TurnBridge` with the same pattern used by `UpdateTokenMapping`:

```go
func (k msgServer) TurnBridge(goCtx context.Context, msg *types.MsgTurnBridge) (*types.MsgTurnBridgeResponse, error) {
    ctx := sdk.UnwrapSDKContext(goCtx)

    // Enforce CanTurnBridge permission
    if !k.HasPermission(ctx, msg.GetSigners(), CanTurnBridge) {
        return nil, errors.Wrap(sdkerrors.ErrUnauthorized, "msg sender is not authorized")
    }

    // Write the bridge-active state (e.g., via gravity keeper or module params)
    if err := k.SetBridgeActive(ctx, msg.Enable); err != nil {
        return nil, err
    }

    return &types.MsgTurnBridgeResponse{}, nil
}
```

The exact state-write call depends on how `bridge_active` is stored (gravity module params or a dedicated key), but the permission check must be present regardless.

---

### Proof of Concept

1. Attacker constructs a valid bech32 address `attacker`.
2. Attacker broadcasts:
   ```
   cronosd tx cronos turn-bridge false --from attacker
   ```
3. The transaction is accepted on-chain with `code=0` — no `ErrUnauthorized` is returned.
4. The bridge state is unchanged (no-op), confirming the handler never executes any logic.
5. Separately, the legitimate admin broadcasts `turn-bridge false` expecting to halt the bridge in an emergency; the transaction also returns `code=0` but the bridge remains active, demonstrating the circuit-breaker is permanently broken. [2](#0-1) [6](#0-5) [7](#0-6)

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

**File:** proto/cronos/tx.proto (L29-30)
```text
  // TurnBridge defines a method to disable or enable the gravity bridge
  rpc TurnBridge(MsgTurnBridge) returns (MsgTurnBridgeResponse);
```

**File:** integration_tests/test_gravity.py (L660-665)
```python
    # turn off bridge
    rsp = cli.turn_bridge("false", from_="community")
    assert rsp["code"] != 0, "should not have the permission"

    rsp = cli.turn_bridge("false", from_="validator")
    assert rsp["code"] == 0, rsp["raw_log"]
```

**File:** docs/architecture/adr-009.md (L36-38)
```markdown
- Assign to each "restricted" messages in Cronos a permission (integer value) and create in Cronos module a mapping between addresses and permissions that is stored in memory. For now, there are only two messages that require permission : MsgUpdateTokenMapping and MsgTurnBridge.
- Create a msg type "MsgUpdatePermissions" that only admin can use and allow to update the address permission mapping.
- Change the logic to always check for the permission before processing the restricted messages.
```
