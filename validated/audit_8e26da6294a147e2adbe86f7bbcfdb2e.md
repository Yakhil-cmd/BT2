The `TurnBridge` implementation is a confirmed stub. Here is the complete picture:

### Title
Missing Permission Check and No-Op Implementation in `msgServer.TurnBridge` — (`x/cronos/keeper/msg_server.go`)

### Summary

`msgServer.TurnBridge` is an unimplemented stub that unconditionally returns `nil, nil`. It performs no authorization check and mutates no state. Any address can broadcast `MsgTurnBridge` and receive a success response, while the bridge state is never actually changed by anyone — including authorized admins.

### Finding Description

`UpdateTokenMapping` correctly gates execution behind `HasPermission`: [1](#0-0) 

`TurnBridge`, which is supposed to apply the same `CanTurnBridge` permission, is a two-line stub: [2](#0-1) 

The permission constant `CanTurnBridge` is defined and the `HasPermission` helper exists and works correctly: [3](#0-2) [4](#0-3) 

`ValidateBasic` on `MsgTurnBridge` only checks that the sender is a valid bech32 address — no authorization: [5](#0-4) 

The ADR and integration tests confirm the intended behavior: unpermissioned callers must be rejected, and the bridge state (`bridge_active`) must be toggled: [6](#0-5) 

### Impact Explanation

There are two simultaneous defects:

1. **Authorization bypass**: Any unprivileged address can submit `MsgTurnBridge` and receive a `nil` error (success). The `CanTurnBridge` permission check is entirely absent.

2. **Broken emergency circuit breaker**: Because the function is a stub, the bridge state is never mutated by anyone — including the CronosAdmin and addresses with `CanTurnBridge`. The emergency bridge-disable mechanism is permanently non-functional. If the bridge needs to be halted (e.g., in response to a gravity bridge exploit), no on-chain action can do so via this message.

The authorization bypass maps directly to the **High** impact category: *Bypass of Cronos admin, governance authority, permission, token-mapping, bridge, block-list, or module-account authorization checks*.

### Likelihood Explanation

The entrypoint is a standard signed transaction, reachable by any funded address on the chain. No special privileges, leaked keys, or external assumptions are required. The bypass is unconditional.

### Recommendation

Implement `TurnBridge` with the same pattern as `UpdateTokenMapping`:

1. Check `HasPermission(ctx, msg.GetSigners(), CanTurnBridge)` and return `sdkerrors.ErrUnauthorized` on failure.
2. Retrieve current params, set `params.EnableGravity` (or the equivalent `bridge_active` field) to `msg.Enable`, and persist via `k.SetParams(ctx, params)`.
3. Emit the appropriate bridge-state-change event.

### Proof of Concept

A unit test calling `msgServer.TurnBridge` with an address that has no permissions and no admin set:

```go
func (suite *KeeperTestSuite) TestTurnBridgeRequiresPermission() {
    suite.SetupTest()
    // ensure no admin is set
    params := suite.app.CronosKeeper.GetParams(suite.ctx)
    params.CronosAdmin = ""
    suite.app.CronosKeeper.SetParams(suite.ctx, params)

    // unpermissioned address
    priv, _ := ethsecp256k1.GenerateKey()
    addr := sdk.AccAddress(common.BytesToAddress(priv.PubKey().Address().Bytes()).Bytes())

    msg := types.NewMsgTurnBridge(addr.String(), false)
    _, err := suite.app.CronosKeeper.TurnBridge(suite.ctx, msg)
    // FAILS: current implementation returns nil, nil unconditionally
    suite.Require().Error(err)
}
```

Current behavior: `err == nil` (stub returns `nil, nil`). Expected behavior: `err` wraps `sdkerrors.ErrUnauthorized`.

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

**File:** x/cronos/keeper/permissions.go (L14-16)
```go
	CanChangeTokenMapping uint64                                  = 1 << iota // 1
	CanTurnBridge                                                             // 2
	All                   = CanChangeTokenMapping | CanTurnBridge             // 3
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

**File:** x/cronos/types/messages.go (L133-141)
```go
// ValidateBasic ...
func (msg *MsgTurnBridge) ValidateBasic() error {
	_, err := sdk.AccAddressFromBech32(msg.Sender)
	if err != nil {
		return errors.Wrapf(sdkerrors.ErrInvalidAddress, "invalid sender address (%s)", err)
	}

	return nil
}
```

**File:** integration_tests/test_gravity.py (L661-665)
```python
    rsp = cli.turn_bridge("false", from_="community")
    assert rsp["code"] != 0, "should not have the permission"

    rsp = cli.turn_bridge("false", from_="validator")
    assert rsp["code"] == 0, rsp["raw_log"]
```
