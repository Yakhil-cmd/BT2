### Title
Bridge Circuit-Breaker is Permanently Non-Functional: `MsgTurnBridge` Handler is a No-Op — (File: x/cronos/keeper/msg_server.go)

---

### Summary

The `TurnBridge` message handler is a stub that returns `nil, nil` without storing any state. Simultaneously, no bridge operation checks a bridge-enabled flag. The result is that the bridge circuit-breaker — intended to halt all bridge flows in an emergency — can never be activated. Unprivileged users continue to execute bridge operations even after a permissioned address has sent `MsgTurnBridge(enable=false)`.

---

### Finding Description

Cronos exposes a bridge circuit-breaker through `MsgTurnBridge`. The full scaffolding exists: a `CanTurnBridge` permission bit, a `CmdTurnBridge` CLI command, and a `MsgTurnBridge` proto message. However, the server-side handler in `msg_server.go` is a complete no-op:

```go
// TurnBridge implements the grpc method
func (k msgServer) TurnBridge(goCtx context.Context, msg *types.MsgTurnBridge) (*types.MsgTurnBridgeResponse, error) {
    return nil, nil
}
``` [1](#0-0) 

The handler accepts the transaction, returns success, and writes nothing to state. No bridge-enabled flag is ever persisted.

Compounding this, none of the bridge execution paths check any such flag:

- `ConvertVouchersToEvmCoins` — performs IBC-voucher-to-EVM-coin conversion with no bridge-enabled guard. [2](#0-1) 

- `IbcTransferCoins` — performs EVM-coin-to-IBC transfer with no bridge-enabled guard. [3](#0-2) 

- `IBCConversionModule.OnRecvPacket` — auto-converts incoming IBC vouchers to EVM coins with no bridge-enabled guard. [4](#0-3) 

The permission system confirms `CanTurnBridge` was intended to gate a real disable path: [5](#0-4) 

---

### Impact Explanation

This is a **High** impact finding: **Bypass of bridge authorization/control mechanism**.

When the admin or a permissioned address sends `MsgTurnBridge{Enable: false}` to halt the bridge during a security incident, the transaction is accepted and returns success, but no state changes. Every bridge operation — `MsgConvertVouchers`, `MsgTransferTokens`, and the IBC auto-conversion middleware — continues to execute without restriction. Unprivileged users can drain or bridge assets through all three paths indefinitely, regardless of the admin's intent to disable the bridge.

This maps directly to the external bug class: operation A (bridge disable) is nominally available, but operation B (bridge execution) is never gated on A, so B remains permanently enabled.

---

### Likelihood Explanation

The circuit-breaker is explicitly designed for emergency use (e.g., a bridge exploit in progress). The broken handler means the emergency stop can never be pulled. Any scenario that would motivate using `MsgTurnBridge` — an active exploit, a compromised relayer, a critical bug — leaves the bridge fully open. The `CanTurnBridge` permission is already granted to specific addresses in production, making the broken path reachable at any time. [6](#0-5) 

---

### Recommendation

1. **Implement the handler**: Store a `bridge_enabled` boolean in the cronos KV store inside `TurnBridge`, keyed by a dedicated prefix.
2. **Add guards to all bridge entry points**: At the top of `ConvertVouchersToEvmCoins`, `IbcTransferCoins`, and `IBCConversionModule.OnRecvPacket`, read the flag and return an error if the bridge is disabled.
3. **Ensure symmetry**: All paths that move assets across the bridge boundary must be gated on the same flag, mirroring the fix recommended in the external report (disallow the dependent operation when the controlling flag is off).

---

### Proof of Concept

1. Admin holds `CanTurnBridge` permission and sends `MsgTurnBridge{Sender: admin, Enable: false}`.
2. Handler at `msg_server.go:84–87` returns `nil, nil` — transaction succeeds, zero state written.
3. Unprivileged user sends `MsgConvertVouchers` with IBC vouchers → EVM coins conversion succeeds; `ConvertVouchersToEvmCoins` has no bridge-enabled check.
4. Unprivileged user sends `MsgTransferTokens` → IBC transfer succeeds; `IbcTransferCoins` has no bridge-enabled check.
5. An incoming IBC packet triggers `IBCConversionModule.OnRecvPacket` → auto-conversion succeeds; no bridge-enabled check.

The bridge is permanently open regardless of any `MsgTurnBridge` call.

### Citations

**File:** x/cronos/keeper/msg_server.go (L84-87)
```go
// TurnBridge implements the grpc method
func (k msgServer) TurnBridge(goCtx context.Context, msg *types.MsgTurnBridge) (*types.MsgTurnBridgeResponse, error) {
	return nil, nil
}
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

**File:** x/cronos/middleware/conversion_middleware.go (L106-147)
```go
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
