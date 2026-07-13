### Title
`MsgTurnBridge` Handler Is a No-Op Stub — Bridge Disable Mechanism Is Permanently Broken (`x/cronos/keeper/msg_server.go`)

### Summary

The `TurnBridge` message handler in Cronos is a complete no-op stub that returns `nil, nil` without performing any permission check or state update. This means the bridge can never be disabled, and bridge operations (`ConvertVouchers`, `TransferTokens`, EVM hooks) proceed unconditionally regardless of any attempted bridge shutdown. Any unprivileged user can also call `TurnBridge` without restriction.

### Finding Description

The `TurnBridge` handler in `x/cronos/keeper/msg_server.go` is implemented as:

```go
// TurnBridge implements the grpc method
func (k msgServer) TurnBridge(goCtx context.Context, msg *types.MsgTurnBridge) (*types.MsgTurnBridgeResponse, error) {
    return nil, nil
}
``` [1](#0-0) 

It does two things wrong simultaneously:

1. **No permission check**: Every other privileged handler checks authorization. `UpdateTokenMapping` checks `CanChangeTokenMapping`, `UpdatePermissions` checks `CronosAdmin`, `StoreBlockList` checks `CronosAdmin`. `TurnBridge` checks nothing — any unprivileged address can submit `MsgTurnBridge` and receive a success response. [2](#0-1) 

2. **No state update**: The handler never writes the bridge-enabled flag. The `bridge_active` / `IsBridgeEnabled` parameter is never toggled. The bridge state remains permanently at its genesis default.

The downstream bridge operations — `ConvertVouchers` → `ConvertVouchersToEvmCoins` and `TransferTokens` → `IbcTransferCoins` — contain no bridge-enabled guard: [3](#0-2) [4](#0-3) 

Similarly, the EVM hook handlers (`SendToIbcHandler`, `SendCroToIbcHandler`, `SendToIbcV2Handler`) registered in `app.go` do not check bridge state before executing IBC transfers: [5](#0-4) 

The `CanTurnBridge` permission bit exists in the permissions system and is tested in integration tests, but the handler that is supposed to consume it is a stub: [6](#0-5) 

### Impact Explanation

**High — Bypass of bridge authorization/control checks.**

The bridge disable mechanism (`MsgTurnBridge`) is the intended emergency control for halting bridge operations. Because the handler is a no-op:

- The bridge can never be disabled, even in an emergency (exploit, depeg, oracle failure).
- Any unprivileged user can submit `MsgTurnBridge` and receive a success response, creating false confidence that the bridge was disabled.
- `ConvertVouchers` and `TransferTokens` — which mint/burn/transfer IBC vouchers and CRC20/CRC21 tokens — continue to execute unconditionally, bypassing the intended bridge authorization gate.

This maps directly to: **High: Bypass of Cronos admin, governance authority, permission, token-mapping, bridge, block-list, or module-account authorization checks.**

### Likelihood Explanation

The `TurnBridge` message is a publicly registered gRPC endpoint callable by any unprivileged user. The no-op stub is present in the current production code. Any user who submits `MsgTurnBridge{Enable: false}` will receive a success response while the bridge remains fully operational.

### Recommendation

Implement `TurnBridge` properly:

1. Add a `CanTurnBridge` permission check (mirroring the pattern in `UpdateTokenMapping`).
2. Persist the bridge-enabled state via `k.SetParams` or a dedicated store key.
3. Add a bridge-enabled guard at the top of `ConvertVouchersToEvmCoins`, `IbcTransferCoins`, and each EVM hook handler, returning an error when the bridge is disabled.

### Proof of Concept

1. Any unprivileged address submits `MsgTurnBridge{Sender: attacker, Enable: false}`.
2. The handler returns `nil, nil` — transaction succeeds, no state written.
3. Admin believes bridge is disabled.
4. Attacker (or anyone) calls `MsgConvertVouchers` or `MsgTransferTokens` — both succeed because no bridge-enabled check exists.
5. IBC vouchers continue to be minted/burned/transferred against the intended disabled state. [7](#0-6)

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

**File:** app/app.go (L851-856)
```go
	app.EvmKeeper.SetHooks(cronoskeeper.NewLogProcessEvmHook(
		evmhandlers.NewSendToAccountHandler(app.BankKeeper, app.CronosKeeper),
		evmhandlers.NewSendToIbcHandler(app.BankKeeper, app.CronosKeeper),
		evmhandlers.NewSendCroToIbcHandler(app.BankKeeper, app.CronosKeeper),
		evmhandlers.NewSendToIbcV2Handler(app.BankKeeper, app.CronosKeeper),
	))
```

**File:** x/cronos/keeper/permissions.go (L1-30)
```go
package keeper

import (
	"github.com/crypto-org-chain/cronos/x/cronos/types"

	sdk "github.com/cosmos/cosmos-sdk/types"
)

// A permission is represented by a bit within uint64 (64bits)
// An address permission is an integer value between 0 and (2^64-1)
// This design allows a quick and simple permission check for addresses
// The next permission should be added before All
const (
	CanChangeTokenMapping uint64                                  = 1 << iota // 1
	CanTurnBridge                                                             // 2
	All                   = CanChangeTokenMapping | CanTurnBridge             // 3
)

func (k Keeper) SetPermissions(ctx sdk.Context, address sdk.AccAddress, permissions uint64) {
	store := ctx.KVStore(k.storeKey)
	permissionsBytes := sdk.Uint64ToBigEndian(permissions)
	store.Set(types.AdminToPermissionsKey(address), permissionsBytes)
}

func (k Keeper) GetPermissions(ctx sdk.Context, address sdk.AccAddress) uint64 {
	store := ctx.KVStore(k.storeKey)
	permissionsBytes := store.Get(types.AdminToPermissionsKey(address))
	return sdk.BigEndianToUint64(permissionsBytes)
}

```
