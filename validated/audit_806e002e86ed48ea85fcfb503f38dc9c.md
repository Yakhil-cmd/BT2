### Title
Pausable External CRC20/CRC21 Contract Blocks IBC Token Conversion in `OnRecvPacket` - (File: `x/cronos/middleware/conversion_middleware.go`, `x/cronos/keeper/evm.go`)

---

### Summary
The Cronos IBC conversion middleware unconditionally calls `mint_by_cronos_module` or `transfer_from_cronos_module` on the registered external CRC20/CRC21 contract during `OnRecvPacket`. If the external contract implements a pause mechanism and is paused, the EVM call reverts, causing `OnRecvPacket` to return an error acknowledgement and permanently blocking all incoming IBC transfers for that token denom as long as the pause persists.

---

### Finding Description

`ConvertCoinFromNativeToCRC21` in `evm.go` explicitly prefers external contracts over auto-deployed ones: [1](#0-0) 

For non-source (IBC-originated) tokens, it calls `mint_by_cronos_module` on the external contract: [2](#0-1) 

For source tokens, it first burns the user's native coins from the bank module, then calls `transfer_from_cronos_module`: [3](#0-2) 

`CallModuleCRC21` packs the call using the `ModuleCRC21` ABI and executes it via `ApplyMessage`. If the external contract's implementation of `mint_by_cronos_module` or `transfer_from_cronos_module` includes a `whenNotPaused` guard (or equivalent), the EVM call reverts and `CallModuleCRC21` returns an error: [4](#0-3) 

This error propagates up through `ConvertCoinFromNativeToCRC21` → `ConvertVouchersToEvmCoins` → `OnRecvPacket` in the IBC conversion middleware. At line 135–142, the middleware returns `NewErrorAcknowledgement(err)`: [5](#0-4) 

Critically, `commit()` is only called on the success path (line 145). Because the entire operation runs inside a `cacheCtx`, the underlying ICS-20 transfer state changes are also discarded when the error ack is returned: [6](#0-5) 

The result: every incoming IBC packet for that denom fails with an error acknowledgement. The sending chain refunds the sender, but the bridge/conversion flow is completely non-functional for all users of that token.

The same failure path is reachable via `MsgConvertVouchers` → `ConvertVouchers` in `msg_server.go`, though there the Cosmos SDK transaction rollback prevents any partial state corruption: [7](#0-6) 

---

### Impact Explanation

All honest users attempting to receive tokens via IBC for the affected denom are blocked for the entire duration the external contract is paused. The IBC channel itself remains open, but every packet for that denom returns an error ack. This matches the allowed **High** impact: *"Permanent or long-lived inability for honest users to process IBC transfers."*

No funds are permanently lost (the sending chain refunds senders), but the bridge/conversion flow is completely non-functional, which is the direct analog to the external report's borrowers being unable to repay debt.

---

### Likelihood Explanation

External CRC20/CRC21 contracts are registered via governance or an authorized `MsgUpdateTokenMapping` transaction. Any such contract that implements a standard `Pausable` pattern (e.g., OpenZeppelin's `Pausable`, or a custom `whenNotPaused` modifier on `mint_by_cronos_module` / `transfer_from_cronos_module`) can trigger this. The contract owner can pause the contract at any time without any Cronos governance action. The Cronos module has no fallback mechanism and no check for whether the external contract is operational before routing IBC packets through it.

---

### Recommendation

In `OnRecvPacket`, if `ConvertVouchersToEvmCoins` fails, the middleware should fall back to delivering the raw IBC vouchers to the receiver (without EVM conversion) rather than returning an error acknowledgement. This mirrors the intentional design already applied to the `OnAcknowledgementPacket` and `OnTimeoutPacket` paths, where conversion failures are logged and silently skipped so the IBC refund is not blocked: [8](#0-7) 

Applying the same "log and continue" pattern to `OnRecvPacket` would ensure IBC transfers succeed even when the external contract is paused, with users retaining their native IBC vouchers and able to retry conversion manually.

---

### Proof of Concept

1. An external CRC20/CRC21 contract implementing `mint_by_cronos_module` with a `whenNotPaused` guard is registered for an IBC denom via `MsgUpdateTokenMapping`.
2. The contract owner calls `pause()` on the external contract.
3. A user on the source chain sends an IBC transfer of that token to Cronos.
4. The relayer submits the IBC `RecvPacket` message on Cronos.
5. `IBCConversionModule.OnRecvPacket` calls `ConvertVouchersToEvmCoins` → `ConvertCoinFromNativeToCRC21` → `CallModuleCRC21("mint_by_cronos_module", sender, amount)`.
6. The external contract reverts with the pause guard. `CallModuleCRC21` returns `"call contract failed"`.
7. `OnRecvPacket` returns `channeltypes.NewErrorAcknowledgement(err)`; `commit()` is never called.
8. The sending chain receives the error ack and refunds the sender.
9. Every subsequent IBC transfer for that denom also fails identically, for as long as the contract remains paused.

### Citations

**File:** x/cronos/keeper/evm.go (L54-68)
```go
// CallModuleCRC21 call a method of ModuleCRC21 contract
func (k Keeper) CallModuleCRC21(ctx sdk.Context, contract common.Address, method string, args ...interface{}) ([]byte, error) {
	data, err := types.ModuleCRC21Contract.ABI.Pack(method, args...)
	if err != nil {
		return nil, err
	}
	_, res, err := k.CallEVM(ctx, &contract, data, big.NewInt(0), DefaultGasCap)
	if err != nil {
		return nil, err
	}
	if res.Failed() {
		return nil, fmt.Errorf("call contract failed: %s, %s, %s", contract.Hex(), method, res.Ret)
	}
	return res.Ret, nil
}
```

**File:** x/cronos/keeper/evm.go (L96-97)
```go
	// external contract is returned in preference to auto-deployed ones
	contract, found := k.GetContractByDenom(ctx, coin.Denom)
```

**File:** x/cronos/keeper/evm.go (L115-129)
```go
	if isSource {
		// burn coins
		err = k.bankKeeper.SendCoinsFromAccountToModule(ctx, sdk.AccAddress(sender.Bytes()), types.ModuleName, sdk.NewCoins(coin))
		if err != nil {
			return err
		}
		err = k.bankKeeper.BurnCoins(ctx, types.ModuleName, coins)
		if err != nil {
			return err
		}
		// unlock crc tokens
		_, err = k.CallModuleCRC21(ctx, contract, "transfer_from_cronos_module", sender, coin.Amount.BigInt())
		if err != nil {
			return err
		}
```

**File:** x/cronos/keeper/evm.go (L136-140)
```go
		// mint crc tokens
		_, err = k.CallModuleCRC21(ctx, contract, "mint_by_cronos_module", sender, coin.Amount.BigInt())
		if err != nil {
			return err
		}
```

**File:** x/cronos/middleware/conversion_middleware.go (L112-146)
```go
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

**File:** x/cronos/middleware/conversion_middleware.go (L179-188)
```go
				); err != nil {
					// Intentional: log and continue so the IBC refund is not blocked.
					// Sender keeps the refunded IBC vouchers and can retry conversion manually.
					im.cronoskeeper.Logger(ctx).Error(
						"failed to convert refund vouchers on acknowledgement",
						"denom", denom,
						"sender", data.Sender,
						"error", err,
					)
				}
```

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
