### Title
Bridge Emergency Pause Is a Silent No-Op, Permanently Bypassing Admin Bridge Control — (`x/cronos/keeper/msg_server.go`)

---

### Summary

The `TurnBridge` message handler, which is the sole mechanism for an authorized admin to pause the Cronos bridge in an emergency, is implemented as a complete no-op. It returns `nil, nil` unconditionally, never writes any state, and no bridge operation ever checks a bridge-enabled flag. The bridge cannot be paused under any circumstances.

---

### Finding Description

`MsgTurnBridge` is a first-class proto-defined transaction surface, has a CLI command, and is explicitly described in ADR-009 as the emergency circuit-breaker for the bridge. The permission system (`CanChangeBridge`) was designed specifically to gate this message. Despite all of this, the server-side implementation is:

```go
// x/cronos/keeper/msg_server.go:85-87
func (k msgServer) TurnBridge(goCtx context.Context, msg *types.MsgTurnBridge) (*types.MsgTurnBridgeResponse, error) {
    return nil, nil
}
``` [1](#0-0) 

The function:
1. Performs no permission check (contrast with `UpdateTokenMapping` at line 73 which calls `k.HasPermission`).
2. Writes no state — no bridge-enabled flag is ever set.
3. Returns success to the caller, so the admin believes the bridge was disabled. [2](#0-1) 

Every bridge entry point — `ConvertVouchersToEvmCoins`, `IbcTransferCoins`, `ConvertCoinFromNativeToCRC21`, `ConvertCoinFromCRC21ToNative`, and all EVM log handlers — proceeds unconditionally with no bridge-state guard: [3](#0-2) [4](#0-3) [5](#0-4) 

The IBC conversion middleware also calls `ConvertVouchersToEvmCoins` with no bridge-state check: [6](#0-5) 

ADR-009 explicitly names bridge disablement as a primary motivation for the permission system: [7](#0-6) 

---

### Impact Explanation

**High — Bypass of Cronos admin bridge authorization.**

When an emergency arises (e.g., a bridge exploit in progress, an upstream IBC channel compromise, or a CRC20 contract vulnerability), the admin sends `MsgTurnBridge{enable: false}`. The transaction is accepted on-chain and returns success. The admin believes the bridge is halted. In reality, every bridge and conversion path continues to execute without restriction. Unprivileged users can continue to bridge, convert, and drain assets through all affected paths (`ConvertVouchers`, `TransferTokens`, EVM `__CronosSendToIbc` / `__CronosSendToEvmChain` hooks, and the IBC conversion middleware) for the entire duration of the emergency. There is no fallback mechanism.

---

### Likelihood Explanation

Certain. The no-op is unconditional — every call to `TurnBridge` silently succeeds and changes nothing. Any scenario that depends on the bridge being pausable (the stated design intent) is permanently broken.

---

### Recommendation

1. Add a `BridgeEnabled bool` (or equivalent) field to the Cronos params or a dedicated KV store key.
2. Implement `TurnBridge` to write this flag and enforce the `CanChangeBridge` permission check (mirroring `UpdateTokenMapping`).
3. Add a guard at the top of `ConvertVouchersToEvmCoins`, `IbcTransferCoins`, `ConvertCoinFromNativeToCRC21`, `ConvertCoinFromCRC21ToNative`, and each EVM log handler that returns an error when the bridge is disabled.
4. Apply the same guard in `IBCConversionModule.OnRecvPacket` before calling `ConvertVouchersToEvmCoins`.

---

### Proof of Concept

1. Authorized admin submits `MsgTurnBridge{sender: admin, enable: false}`.
2. Transaction succeeds on-chain (`code: 0`), admin observes success.
3. Unprivileged user calls `MsgConvertVouchers` or emits `__CronosSendToIbc` from a CRC20 contract.
4. `ConvertVouchersToEvmCoins` / `IbcTransferCoins` execute without any bridge-state check and complete successfully.
5. Bridge operations continue indefinitely; the admin's emergency pause has zero effect.

### Citations

**File:** x/cronos/keeper/msg_server.go (L68-87)
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

**File:** x/cronos/keeper/evm.go (L90-144)
```go
// ConvertCoinFromNativeToCRC21 convert native token to erc20 token
func (k Keeper) ConvertCoinFromNativeToCRC21(ctx sdk.Context, sender common.Address, coin sdk.Coin, autoDeploy bool) error {
	if !types.IsValidCoinDenom(coin.Denom) {
		return fmt.Errorf("coin %s is not supported for conversion", coin.Denom)
	}
	var err error
	// external contract is returned in preference to auto-deployed ones
	contract, found := k.GetContractByDenom(ctx, coin.Denom)
	if !found {
		if !autoDeploy {
			return fmt.Errorf("no contract found for the denom %s", coin.Denom)
		}
		contract, err = k.DeployModuleCRC21(ctx, coin.Denom)
		if err != nil {
			return err
		}
		if err = k.SetAutoContractForDenom(ctx, coin.Denom, contract); err != nil {
			return err
		}

		k.Logger(ctx).Info(fmt.Sprintf("contract address %s created for coin denom %s", contract.String(), coin.Denom))
	}

	isSource := types.IsSourceCoin(coin.Denom)
	coins := sdk.NewCoins(coin)
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
	} else {
		// send coins to contract address
		err = k.bankKeeper.SendCoins(ctx, sdk.AccAddress(sender.Bytes()), sdk.AccAddress(contract.Bytes()), coins)
		if err != nil {
			return err
		}
		// mint crc tokens
		_, err = k.CallModuleCRC21(ctx, contract, "mint_by_cronos_module", sender, coin.Amount.BigInt())
		if err != nil {
			return err
		}
	}

	return nil
}
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

**File:** docs/architecture/adr-009.md (L8-12)
```markdown
Some messages in cronos require permissions. For example, changing the mapping to support new CRC20 auto-conversion contracts or disabling the bridge module in case of emergency. Right now, only the admin has the ability to use those messages.
 The admin is a single address defined in cronos space and can be modified through governance. It is usually a multi-sig address shared by multiple trusted parties in order to achieve a higher level of security.

While a single multi-sig admin address was originally implemented with simplicity in mind, realistically it is not practical to rely on a single address to perform all admin tasks.
As those operations could become more frequent (updating the token mapping) or needs to be triggered by external systems (circuit breaker for gravity module), it would be more practical to define a granular permission system which restricts certain operations to only some known addresses.
```
