### Title
`TurnBridge` Message Handler Is a Silent No-Op, Permanently Preventing Admin Bridge Shutdown - (File: `x/cronos/keeper/msg_server.go`)

### Summary
The `TurnBridge` gRPC message handler in `msg_server.go` unconditionally returns `nil, nil` without executing any state change. An admin calling `MsgTurnBridge` to disable the bridge receives a success response, but the bridge state is never modified. Unprivileged users can continue to use bridge/conversion flows indefinitely, even after an emergency shutdown is attempted.

### Finding Description
The `TurnBridge` function in `x/cronos/keeper/msg_server.go` is implemented as a stub that always returns success:

```go
func (k msgServer) TurnBridge(goCtx context.Context, msg *types.MsgTurnBridge) (*types.MsgTurnBridgeResponse, error) {
    return nil, nil
}
``` [1](#0-0) 

This is the direct analog to the external report's `return (30_000e18, 0)` pattern: a function that is supposed to perform a meaningful state-changing operation instead silently returns a constant success value, bypassing all intended logic. The function is part of the `MsgServer` interface and is reachable via any signed transaction submitting a `MsgTurnBridge` message.

The other message handlers in the same file (`ConvertVouchers`, `TransferTokens`, `UpdateTokenMapping`, `UpdateParams`, `UpdatePermissions`, `StoreBlockList`) all perform real state mutations. [2](#0-1) 

### Impact Explanation
`MsgTurnBridge` is the admin's mechanism to halt bridge operations in an emergency (e.g., a critical vulnerability is discovered in the IBC transfer or CRC20 conversion path). Because the handler is a no-op, the bridge state is never changed. Unprivileged users can continue to call `ConvertVouchers`, `TransferTokens`, and the EVM hook handlers (`SendToIbcHandler`, `SendCroToIbcHandler`) that route through `IbcTransferCoins` and `ConvertCoinFromNativeToCRC21` — all of which remain fully operational regardless of any `TurnBridge` call.

This is a **High** impact finding: it constitutes a bypass of Cronos admin authority over bridge/conversion flows. The admin's control over the bridge is permanently nullified by the stub implementation. [3](#0-2) [4](#0-3) 

### Likelihood Explanation
The entry path is straightforward: any account with admin authority submits a `MsgTurnBridge` transaction. The transaction is accepted, fees are paid, a success response is returned, but no bridge state is written. The admin has no indication the operation failed. Any unprivileged user who continues to use the bridge after the supposed shutdown is exploiting this gap.

### Recommendation
Implement `TurnBridge` to actually read `msg.Enable` and persist a bridge-enabled flag to the module's param store (or a dedicated KV key), then gate `IbcTransferCoins`, `ConvertVouchersToEvmCoins`, and the EVM hook handlers on that flag. At minimum, return an explicit error (`errors.New("not implemented")`) so callers are not silently misled.

### Proof of Concept

1. Admin submits `MsgTurnBridge{Enable: false}` to disable the bridge.
2. The transaction is included in a block; `TurnBridge` executes and returns `nil, nil` — no state is written.
3. Admin observes a successful tx receipt and believes the bridge is disabled.
4. An unprivileged user calls `MsgConvertVouchers` or emits a `__CronosSendToIbc` EVM log.
5. `ConvertVouchersToEvmCoins` / `IbcTransferCoins` execute normally — no bridge-enabled check exists — and the transfer succeeds.
6. The bridge is never actually disabled; the admin's emergency shutdown had zero effect. [1](#0-0) [5](#0-4)

### Citations

**File:** x/cronos/keeper/msg_server.go (L27-100)
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
}

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

func (k msgServer) UpdateParams(goCtx context.Context, msg *types.MsgUpdateParams) (*types.MsgUpdateParamsResponse, error) {
	if msg.Authority != k.authority {
		return nil, errors.Wrapf(govtypes.ErrInvalidSigner, "invalid authority; expected %s, got %s", k.authority, msg.Authority)
	}

	ctx := sdk.UnwrapSDKContext(goCtx)
	if err := k.SetParams(ctx, msg.Params); err != nil {
		return nil, err
	}

	return &types.MsgUpdateParamsResponse{}, nil
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

**File:** x/cronos/keeper/ibc.go (L80-100)
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
```

**File:** x/cronos/keeper/evmhandlers/send_cro_to_ibc.go (L95-103)
```go
	// First, transfer IBC coin to user so that he will be the refunded address if transfer fails
	if err = h.bankKeeper.SendCoins(ctx, contractAddr, sender, coins); err != nil {
		return err
	}
	// Initiate IBC transfer from sender account
	if err = h.cronosKeeper.IbcTransferCoins(ctx, sender.String(), recipient, coins, ""); err != nil {
		return err
	}
	return nil
```
