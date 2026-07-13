### Title
`MsgTurnBridge` Handler Is a No-Op Stub — Bridge Cannot Be Disabled and Permission Check Is Absent - (File: x/cronos/keeper/msg_server.go)

### Summary

The `TurnBridge` gRPC message handler in `x/cronos/keeper/msg_server.go` is implemented as a complete no-op: it performs no permission check and writes no state, returning `nil, nil` unconditionally. The bridge-active flag is therefore never set, and neither `ConvertVouchers` nor `TransferTokens` ever consults such a flag. Any unprivileged address can call `TurnBridge` and receive a success response, and the admin's emergency circuit-breaker for the bridge is permanently non-functional.

### Finding Description

`MsgTurnBridge` is a registered Cosmos SDK message with a dedicated permission bit (`CanTurnBridge`) and a CLI command (`turn-bridge`). Its intended purpose — documented in ADR-009 and the proto comments — is to allow an authorized address to disable or re-enable the bridge in an emergency.

The actual handler implementation is:

```go
// TurnBridge implements the grpc method
func (k msgServer) TurnBridge(goCtx context.Context, msg *types.MsgTurnBridge) (*types.MsgTurnBridgeResponse, error) {
    return nil, nil
}
``` [1](#0-0) 

Compare this with the analogous `UpdateTokenMapping` handler, which correctly gates on `HasPermission`:

```go
if !k.HasPermission(ctx, msg.GetSigners(), CanChangeTokenMapping) {
    return nil, errors.Wrap(sdkerrors.ErrUnauthorized, "msg sender is not authorized")
}
``` [2](#0-1) 

Because `TurnBridge` writes nothing, there is no `bridge_active` (or equivalent) field in the cronos `Params` that could be set to `false`. Consequently, `ConvertVouchers` and `TransferTokens` — the two bridge entry points — contain no guard against a disabled bridge:

```go
func (k msgServer) ConvertVouchers(...) {
    err := k.ConvertVouchersToEvmCoins(ctx, msg.Address, msg.Coins)
    ...
}
func (k msgServer) TransferTokens(...) {
    err := k.IbcTransferCoins(ctx, msg.From, msg.To, msg.Coins, "")
    ...
}
``` [3](#0-2) 

The IBC conversion middleware's `OnRecvPacket` path also calls `ConvertVouchersToEvmCoins` with no bridge-active check: [4](#0-3) 

The EVM hook `SendToIbcHandler` similarly calls `IbcTransferCoins` with no bridge-active guard: [5](#0-4) 

### Impact Explanation

**High — Bypass of Cronos admin/governance bridge authorization.**

The `CanTurnBridge` permission bit and the `MsgTurnBridge` message exist precisely to give the admin an emergency circuit-breaker. Because the handler is a no-op:

1. **Any unprivileged address** can submit `MsgTurnBridge` and receive a success response — the permission check that should mirror `UpdateTokenMapping`'s `HasPermission` guard is entirely absent.
2. **The bridge can never be disabled.** Even the admin calling `TurnBridge(false)` has zero effect. `ConvertVouchers`, `TransferTokens`, the IBC middleware conversion path, and the `__CronosSendToIbc` EVM hook all continue to execute bridge operations unconditionally.

In an emergency (e.g., a vulnerability in the conversion logic or a compromised token mapping), the admin's only documented mechanism to halt bridge flows is silently inoperative, allowing continued unauthorized minting/burning/transfer of IBC vouchers and CRC20/CRC21 tokens.

### Likelihood Explanation

The `TurnBridge` stub is reachable by any address via the standard Cosmos SDK message path. The permission bypass (anyone can call it) is trivially exploitable. The inability to disable the bridge is a permanent condition until the handler is implemented. The integration test `test_gravity_turn_bridge` exercises the bridge-off path but only tests the Gravity Bridge module's `bridge_active` parameter — it does not exercise the `MsgTurnBridge` Cosmos message handler, so the stub has gone undetected.

### Recommendation

1. **Implement the permission check** in `TurnBridge`, mirroring `UpdateTokenMapping`:
   ```go
   if !k.HasPermission(ctx, msg.GetSigners(), CanTurnBridge) {
       return nil, errors.Wrap(sdkerrors.ErrUnauthorized, "msg sender is not authorized")
   }
   ```
2. **Persist the bridge-active state** — add a `BridgeActive bool` field to `Params` (or a dedicated KV key) and set it from the handler.
3. **Add a guard** at the top of `ConvertVouchers`, `TransferTokens`, and `OnRecvPacket` (conversion middleware) that returns an error when the bridge is disabled.
4. **Add a guard** in `SendToIbcHandler.handle` and any other EVM hook that initiates bridge transfers.

### Proof of Concept

```go
// Any unprivileged address can call TurnBridge and receive success:
msg := types.NewMsgTurnBridge(unprivilegedAddr.String(), false)
_, err := msgSrv.TurnBridge(ctx, msg)
// err == nil  ← succeeds with no permission check

// Bridge operations continue unaffected:
convertMsg := types.NewMsgConvertVouchers(userAddr.String(), ibcCoins)
_, err = msgSrv.ConvertVouchers(ctx, convertMsg)
// err == nil  ← bridge not disabled; IBC vouchers converted to EVM coins
```

The `TurnBridge` handler at [1](#0-0)  returns `nil, nil` unconditionally, so the second call succeeds regardless of the first. The permission constants confirm `CanTurnBridge` is defined but never enforced in the handler: [6](#0-5)

### Citations

**File:** x/cronos/keeper/msg_server.go (L27-65)
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
```

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

**File:** x/cronos/middleware/conversion_middleware.go (L105-146)
```go
// OnRecvPacket implements the IBCModule interface.
func (im IBCConversionModule) OnRecvPacket(
	ctx sdk.Context,
	channelVersion string,
	packet channeltypes.Packet,
	relayer sdk.AccAddress,
) exported.Acknowledgement {
	cacheCtx, commit := ctx.CacheContext()
	ack := im.app.OnRecvPacket(cacheCtx, channelVersion, packet, relayer)
	if !ack.Success() {
		// Underlying transfer failed: discard cacheCtx writes and return the
		// failure ack. Committing would persist a half-applied transfer.
		return ack
	}
	data, err := transferTypes.UnmarshalPacketData(packet.GetData(), channelVersion, "")
	if err != nil {
		return channeltypes.NewErrorAcknowledgement(errors.Wrap(sdkerrors.ErrUnknownRequest,
			"cannot unmarshal ICS-20 transfer packet data in middleware"))
	}
	denom := im.getIbcDenomFromPacketAndData(packet, data.Token)
	if im.canBeConverted(cacheCtx, denom) {
		transferAmount, ok := sdkmath.NewIntFromString(data.Token.Amount)
		if !ok {
			return channeltypes.NewErrorAcknowledgement(errors.Wrapf(
				transferTypes.ErrInvalidAmount,
				"unable to parse transfer amount (%s) into sdk.Int in middleware",
				data.Token.Amount,
			))
		}
		token := sdk.NewCoin(denom, transferAmount)
		if err := im.cronoskeeper.ConvertVouchersToEvmCoins(cacheCtx, data.Receiver, sdk.NewCoins(token)); err != nil {
			im.cronoskeeper.Logger(ctx).Error(
				"failed to convert vouchers on recv",
				"denom", denom,
				"receiver", data.Receiver,
				"error", err,
			)
			return channeltypes.NewErrorAcknowledgement(err)
		}
	}
	commit()
	return ack
```

**File:** x/cronos/keeper/evmhandlers/send_to_ibc.go (L86-133)
```go
func (h SendToIbcHandler) handle(
	ctx sdk.Context,
	contract common.Address,
	senderAddress common.Address,
	recipient string,
	amountInt *big.Int,
	id *big.Int,
) error {
	denom, found := h.cronosKeeper.GetDenomByContract(ctx, contract)
	if !found {
		return fmt.Errorf("contract %s is not connected to native token", contract)
	}

	if !types.IsValidIBCDenom(denom) && !types.IsValidCronosDenom(denom) {
		return fmt.Errorf("the native token associated with the contract %s is neither an ibc voucher or a cronos token", contract)
	}

	contractAddr := sdk.AccAddress(contract.Bytes())
	sender := sdk.AccAddress(senderAddress.Bytes())
	amount := sdkmath.NewIntFromBigInt(amountInt)
	coins := sdk.NewCoins(sdk.NewCoin(denom, amount))

	var err error
	if types.IsSourceCoin(denom) {
		// it is a source token, we need to mint coins
		if err = h.bankKeeper.MintCoins(ctx, types.ModuleName, coins); err != nil {
			return err
		}
		// send the coin to the user
		if err = h.bankKeeper.SendCoinsFromModuleToAccount(ctx, types.ModuleName, sender, coins); err != nil {
			return err
		}
	} else {
		// First, transfer IBC coin to user so that he will be the refunded address if transfer fails
		if err = h.bankKeeper.SendCoins(ctx, contractAddr, sender, coins); err != nil {
			return err
		}
	}

	channelId := ""
	if id != nil {
		channelId = "channel-" + id.String()
	}
	// Initiate IBC transfer from sender account
	if err = h.cronosKeeper.IbcTransferCoins(ctx, sender.String(), recipient, coins, channelId); err != nil {
		return err
	}
	return nil
```

**File:** x/cronos/keeper/permissions.go (L13-17)
```go
const (
	CanChangeTokenMapping uint64                                  = 1 << iota // 1
	CanTurnBridge                                                             // 2
	All                   = CanChangeTokenMapping | CanTurnBridge             // 3
)
```
