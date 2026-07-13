### Title
`TurnBridge` Message Handler is a No-Op, Permanently Bypassing Bridge Disable Control — (File: `x/cronos/keeper/msg_server.go`)

---

### Summary

The `TurnBridge` message handler is completely unimplemented. It returns `(nil, nil)` without checking permissions, writing any state, or performing any action. The `CanTurnBridge` permission defined in the permissions system is never enforced. As a result, the bridge can never be disabled: any admin call to `MsgTurnBridge` silently succeeds with no effect, and unprivileged users can continue to bridge tokens indefinitely regardless of admin intent.

---

### Finding Description

The external bug class is a **missing state guard**: a critical operation (`withdrawCredit`) lacks a check against a protocol state (`marketStatus != Trading`), allowing a party to exit a position that should be locked. The Cronos analog is structurally identical: the mechanism that is supposed to set the "bridge disabled" state is itself a no-op, so the guard can never be activated and bridge operations are permanently unlocked.

**Root cause — `TurnBridge` is a no-op:** [1](#0-0) 

```go
func (k msgServer) TurnBridge(goCtx context.Context, msg *types.MsgTurnBridge) (*types.MsgTurnBridgeResponse, error) {
    return nil, nil
}
```

The handler:
1. Does **not** check the `CanTurnBridge` permission.
2. Does **not** write any "bridge enabled/disabled" flag to state.
3. Returns a success response unconditionally.

**`CanTurnBridge` permission is defined but never enforced:** [2](#0-1) 

The permission bit `CanTurnBridge = 2` exists in the permission system alongside `CanChangeTokenMapping`, but no code path ever calls `HasPermission(..., CanTurnBridge)`.

**Bridge operations have no "bridge enabled" guard:**

`ConvertVouchersToEvmCoins` and `IbcTransferCoins` — the two functions that execute all bridge activity — contain no check against any bridge-enabled flag: [3](#0-2) [4](#0-3) 

These are called directly from the `MsgConvertVouchers` and `MsgTransferTokens` message handlers: [5](#0-4) 

The IBC conversion middleware's `OnRecvPacket` also calls `ConvertVouchersToEvmCoins` with no bridge-state check: [6](#0-5) 

---

### Impact Explanation

**High — Bypass of Cronos admin bridge authorization check.**

The bridge control mechanism is completely inoperative. An admin who calls `MsgTurnBridge` to disable the bridge during a security incident (e.g., a discovered exploit in the conversion logic, a compromised IBC channel, or an accounting discrepancy) receives a success response but achieves nothing. Unprivileged users can continue to:

- Convert IBC vouchers to EVM coins via `MsgConvertVouchers`.
- Transfer EVM tokens out via `MsgTransferTokens`.
- Trigger bridge operations via EVM log hooks (`SendToIbcHandler`, `SendCroToIbcHandler`).
- Receive and auto-convert incoming IBC packets via the middleware.

The bridge is permanently active with no mechanism to halt it, directly bypassing the admin bridge authorization control.

---

### Likelihood Explanation

The entry paths (`MsgConvertVouchers`, `MsgTransferTokens`, EVM hooks, IBC middleware) are all unprivileged and publicly reachable. The only precondition is that an admin has attempted to disable the bridge — a scenario that is precisely the moment the control is needed. The no-op handler makes the bypass unconditional and automatic.

---

### Recommendation

1. **Implement `TurnBridge`**: Check `CanTurnBridge` permission, then persist a `BridgeEnabled bool` field in the module params (or a dedicated KV key).

2. **Add a bridge-enabled guard** at the top of `ConvertVouchersToEvmCoins` and `IbcTransferCoins`:
   ```go
   if !k.GetParams(ctx).EnableBridge {
       return errorsmod.Wrap(types.ErrBridgeDisabled, "bridge is currently disabled")
   }
   ```

3. **Guard the IBC middleware** `OnRecvPacket` conversion path with the same check so incoming auto-conversion is also halted when the bridge is off.

---

### Proof of Concept

1. Admin holds `CanTurnBridge` permission and calls `MsgTurnBridge{Enable: false}`.
2. The handler at `msg_server.go:85–87` returns `nil, nil` — no state is written, no error is returned.
3. Unprivileged user calls `MsgConvertVouchers` with IBC CRO vouchers.
4. `ConvertVouchersToEvmCoins` executes without any bridge-state check, mints EVM tokens, and completes successfully.
5. The bridge is never disabled; the admin's control action had zero effect.

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

**File:** x/cronos/keeper/ibc.go (L21-78)
```go
func (k Keeper) ConvertVouchersToEvmCoins(ctx sdk.Context, from string, coins sdk.Coins) error {
	acc, err := sdk.AccAddressFromBech32(from)
	if err != nil {
		return err
	}

	params := k.GetParams(ctx)
	evmParams := k.GetEvmParams(ctx)
	for _, c := range coins {
		switch c.Denom {
		case params.IbcCroDenom:
			if params.IbcCroDenom == "" {
				return errorsmod.Wrap(types.ErrIbcCroDenomEmpty, "ibc is disabled")
			}

			// Send ibc tokens to escrow address
			err := k.bankKeeper.SendCoinsFromAccountToModule(ctx, acc, types.ModuleName, sdk.NewCoins(c))
			if err != nil {
				return err
			}
			// Compute new amount, because basecro is a 8 decimals token, we need to multiply by 10^10 to make it
			// a 18 decimals token
			amount18dec := sdk.NewCoin(evmParams.EvmDenom, c.Amount.Mul(sdkmath.NewIntFromBigInt(types.TenPowTen)))

			// Mint new evm tokens
			if err := k.bankKeeper.MintCoins(
				ctx, types.ModuleName, sdk.NewCoins(amount18dec),
			); err != nil {
				return err
			}

			// Send evm tokens to receiver
			if err := k.bankKeeper.SendCoinsFromModuleToAccount(
				ctx, types.ModuleName, acc, sdk.NewCoins(amount18dec),
			); err != nil {
				return err
			}

		default:
			err := k.ConvertCoinFromNativeToCRC21(ctx, common.BytesToAddress(acc.Bytes()), c, params.EnableAutoDeployment)
			if err != nil {
				return err
			}
		}
	}
	defer func() {
		for _, a := range coins {
			if a.Amount.IsInt64() {
				telemetry.SetGaugeWithLabels(
					[]string{"tx", "msg", "ConvertVouchersToEvmCoins"},
					float32(a.Amount.Int64()),
					[]metrics.Label{telemetry.NewLabel("denom", a.Denom)},
				)
			}
		}
	}()
	return nil
}
```

**File:** x/cronos/keeper/ibc.go (L80-159)
```go
func (k Keeper) IbcTransferCoins(ctx sdk.Context, from, destination string, coins sdk.Coins, channelId string) error {
	acc, err := sdk.AccAddressFromBech32(from)
	if err != nil {
		return err
	}

	if len(destination) == 0 {
		return errors.New("to address cannot be empty")
	}

	params := k.GetParams(ctx)
	evmParams := k.GetEvmParams(ctx)

	for _, c := range coins {
		switch c.Denom {
		case evmParams.EvmDenom:
			// Compute the remainder, we won't transfer anything lower than 10^10
			amount8decRem := c.Amount.Mod(sdkmath.NewIntFromBigInt(types.TenPowTen))
			amountToBurn := c.Amount.Sub(amount8decRem)
			if amountToBurn.IsZero() {
				// Amount too small
				continue
			}
			coins := sdk.NewCoins(sdk.NewCoin(evmParams.EvmDenom, amountToBurn))

			// Send evm tokens to escrow address
			err := k.bankKeeper.SendCoinsFromAccountToModule(ctx, acc, types.ModuleName, coins)
			if err != nil {
				return err
			}
			// Burns the evm tokens
			if err := k.bankKeeper.BurnCoins(
				ctx, types.ModuleName, coins); err != nil {
				return err
			}

			// Transfer ibc tokens back to the user
			// We divide by 10^10 to come back to an 8decimals token
			amount8dec := c.Amount.Quo(sdkmath.NewIntFromBigInt(types.TenPowTen))
			ibcCoin := sdk.NewCoin(params.IbcCroDenom, amount8dec)
			if err := k.bankKeeper.SendCoinsFromModuleToAccount(
				ctx, types.ModuleName, acc, sdk.NewCoins(ibcCoin),
			); err != nil {
				return err
			}

			// No need to specify the channelId because it's not a source token
			err = k.ibcSendTransfer(ctx, acc, destination, ibcCoin, "")
			if err != nil {
				return err
			}

		default:
			if !types.IsValidIBCDenom(c.Denom) && !types.IsValidCronosDenom(c.Denom) {
				return fmt.Errorf("the coin %s is neither an ibc voucher or a cronos token", c.Denom)
			}
			_, found := k.GetContractByDenom(ctx, c.Denom)
			if !found {
				return fmt.Errorf("coin %s is not supported", c.Denom)
			}
			err = k.ibcSendTransfer(ctx, acc, destination, c, channelId)
			if err != nil {
				return err
			}
		}
	}

	defer func() {
		for _, a := range coins {
			if a.Amount.IsInt64() {
				telemetry.SetGaugeWithLabels(
					[]string{"tx", "msg", "IbcTransferCoins"},
					float32(a.Amount.Int64()),
					[]metrics.Label{telemetry.NewLabel("denom", a.Denom)},
				)
			}
		}
	}()
	return nil
}
```

**File:** x/cronos/middleware/conversion_middleware.go (L105-147)
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
}
```
