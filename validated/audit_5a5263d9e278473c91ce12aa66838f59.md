### Title
Bridge State Never Set or Checked: `TurnBridge` No-Op Allows Bridge Operations to Permanently Bypass Admin Shutdown - (File: x/cronos/keeper/msg_server.go)

### Summary
The `TurnBridge` message handler is a complete no-op, returning `nil, nil` without setting any bridge-enabled/disabled state. `ConvertVouchers` and `TransferTokens` never check any bridge state before executing. The `CanTurnBridge` permission exists in the codebase but is never exercised. The result is that the admin's intended bridge-shutdown mechanism is permanently inoperative: bridge operations proceed unconditionally regardless of any admin intent to halt them.

### Finding Description
`TurnBridge` in `msg_server.go` lines 85–87 is:

```go
func (k msgServer) TurnBridge(goCtx context.Context, msg *types.MsgTurnBridge) (*types.MsgTurnBridgeResponse, error) {
    return nil, nil
}
```

It does not:
- Check the `CanTurnBridge` permission (contrast with `UpdateTokenMapping` at line 73 which checks `CanChangeTokenMapping`)
- Write any bridge-enabled flag to the KV store
- Return any error

The `CanTurnBridge` constant is defined in `permissions.go` at line 15 alongside `CanChangeTokenMapping`, making clear the design intent: a privileged actor should be able to halt the bridge. Yet `ConvertVouchers` (lines 27–45) and `TransferTokens` (lines 47–66) in `msg_server.go` contain no bridge-state guard whatsoever before calling `ConvertVouchersToEvmCoins` and `IbcTransferCoins` respectively. The EVM hook `PostTxProcessing` in `evm_hooks.go` (lines 28–44) similarly dispatches all matching log handlers with no bridge-state check.

This is the direct Cronos analog to the AMM `funding()` bug: the specification/design implies a state requirement (bridge must be enabled), but the implementation performs no state check, so the sensitive operation executes unconditionally.

### Impact Explanation
**High — Bypass of Cronos admin bridge authorization control.**

When a security incident requires halting the bridge (e.g., a bug in `ConvertVouchersToEvmCoins`, an IBC accounting exploit, or a CRC20/CRC21 minting flaw), the admin has no effective mechanism to stop it. Any unprivileged user can continue calling `ConvertVouchers` or `TransferTokens`, or trigger the EVM hook path via a contract `__CronosSendToIbc` / `__CronosSendToEvmChain` event, causing ongoing unauthorized bridge/conversion flows — minting CRC20/CRC21 tokens or releasing IBC vouchers — even after the admin has attempted to shut down the bridge.

### Likelihood Explanation
The condition is permanent and unconditional: `TurnBridge` has never functioned. Every block since deployment, bridge operations have been uncheckable by the admin. Any user who calls `ConvertVouchers` or `TransferTokens`, or any contract that emits a bridge event, exercises this path.

### Recommendation
1. Implement `TurnBridge` to write a `bridge_enabled` boolean flag to the KV store, gated behind the `CanTurnBridge` permission check (mirroring the pattern in `UpdateTokenMapping`).
2. Add a guard at the top of `ConvertVouchers`, `TransferTokens`, and `PostTxProcessing` (or the individual EVM log handlers) that reads the flag and returns an error (or silently skips, as the AMM fix did) when the bridge is disabled.
3. Ensure the flag defaults to `true` on genesis so existing behavior is preserved until an admin explicitly disables it.

### Proof of Concept
1. Admin calls `MsgTurnBridge{enable: false}` — `TurnBridge` returns `(nil, nil)`; no state is written.
2. Attacker calls `MsgConvertVouchers{address: attacker, coins: [...]}` — `ConvertVouchers` calls `ConvertVouchersToEvmCoins` with no bridge-state check; tokens are minted to the attacker's EVM address.
3. Alternatively, attacker deploys a contract that emits `__CronosSendToIbc`; `PostTxProcessing` dispatches the handler and initiates an IBC transfer with no bridge-state check.
4. Bridge operations continue indefinitely regardless of admin intent. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5)

### Citations

**File:** x/cronos/keeper/msg_server.go (L27-45)
```go
func (k msgServer) ConvertVouchers(goCtx context.Context, msg *types.MsgConvertVouchers) (*types.MsgConvertVouchersResponse, error) {
	ctx := sdk.UnwrapSDKContext(goCtx)
	err := k.ConvertVouchersToEvmCoins(ctx, msg.Address, msg.Coins)
	if err != nil {
		return nil, err
	}

	// emit events
	ctx.EventManager().EmitEvents(sdk.Events{
		types.NewConvertVouchersEvent(msg.Address, msg.Coins),
		sdk.NewEvent(
			sdk.EventTypeMessage,
			sdk.NewAttribute(sdk.AttributeKeyModule, types.ModuleName),
		),
	},
	)

	return &types.MsgConvertVouchersResponse{}, nil
}
```

**File:** x/cronos/keeper/msg_server.go (L47-66)
```go
func (k msgServer) TransferTokens(goCtx context.Context, msg *types.MsgTransferTokens) (*types.MsgTransferTokensResponse, error) {
	ctx := sdk.UnwrapSDKContext(goCtx)
	// TODO change the msg to be able to specify the channel id
	// Only sending non source token is supported at the moment
	err := k.IbcTransferCoins(ctx, msg.From, msg.To, msg.Coins, "")
	if err != nil {
		return nil, err
	}

	// emit events
	ctx.EventManager().EmitEvents(sdk.Events{
		types.NewTransferTokensEvent(msg.From, msg.To, msg.Coins),
		sdk.NewEvent(
			sdk.EventTypeMessage,
			sdk.NewAttribute(sdk.AttributeKeyModule, types.ModuleName),
		),
	},
	)
	return &types.MsgTransferTokensResponse{}, nil
}
```

**File:** x/cronos/keeper/msg_server.go (L69-82)
```go
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

**File:** x/cronos/keeper/msg_server.go (L85-87)
```go
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

**File:** x/cronos/keeper/evm_hooks.go (L28-44)
```go
func (h LogProcessEvmHook) PostTxProcessing(ctx sdk.Context, _ *core.Message, receipt *ethtypes.Receipt) error {
	addLogToReceiptFunc := newFuncAddLogToReceipt(receipt)
	for _, log := range receipt.Logs {
		if len(log.Topics) == 0 {
			continue
		}
		handler, ok := h.handlers[log.Topics[0]]
		if !ok {
			continue
		}
		err := handler.Handle(ctx, log.Address, log.Topics, log.Data, addLogToReceiptFunc)
		if err != nil {
			return err
		}
	}
	return nil
}
```
