### Title
Admin Token-Mapping Delist Silently Bypassed for Auto-Deployed Contracts — (`x/cronos/keeper/keeper.go`)

### Summary

When the Cronos admin attempts to delist a token by calling `RegisterOrUpdateTokenMapping` with an empty contract address, only the external contract mapping is removed via `DeleteExternalContractForDenom`. Any auto-deployed contract mapping for the same denom is left fully intact and active. Because `GetContractByDenom` falls back to the auto contract, `canBeConverted` continues to return `true`, IBC receive auto-conversion continues, and `IbcTransferCoins` continues to accept the denom. The delist operation silently returns success while having no effect on the auto-contract path.

### Finding Description

`RegisterOrUpdateTokenMapping` handles the "delete" case (empty `msg.Contract`) by calling `DeleteExternalContractForDenom`: [1](#0-0) 

`DeleteExternalContractForDenom` only removes the `DenomToExternalContractKey` entry. If an auto contract also exists for the denom, it explicitly **re-establishes** the reverse mapping for the auto contract before returning: [2](#0-1) 

There is no `DeleteAutoContractForDenom` function anywhere in the keeper, and `RegisterOrUpdateTokenMapping` has no code path that touches `DenomToAutoContractKey`. After the admin's delist call, `GetContractByDenom` still resolves the denom to the auto contract: [3](#0-2) 

The IBC conversion middleware's `canBeConverted` guard calls `GetContractByDenom` and returns `true` as long as any mapping (including auto) exists: [4](#0-3) 

`IbcTransferCoins` performs the same check and continues to allow outbound IBC transfers of the supposedly-delisted denom: [5](#0-4) 

`OnRecvPacket` in the middleware calls `ConvertVouchersToEvmCoins` for any denom where `canBeConverted` is true, so inbound IBC packets still auto-convert the delisted token: [6](#0-5) 

Additionally, the `SendToIbcHandler` EVM hook resolves the denom from the auto contract address via `GetDenomByContract`, which cross-checks against `GetContractByDenom`. Since the auto contract is still the active mapping, this cross-check passes and the EVM hook continues to process `__CronosSendToIbc` events emitted by the auto contract: [7](#0-6) [8](#0-7) 

The spec itself documents this gap: *"There's no way to delete a token mapping currently."* [9](#0-8) 

### Impact Explanation

The admin's token-mapping delist is silently bypassed for any denom that has an auto-deployed contract. All three bridge/conversion surfaces — inbound IBC auto-conversion, outbound `MsgTransferTokens`, and the `__CronosSendToIbc` EVM hook — remain fully operational after the delist attempt. If the reason for delisting is a security concern (e.g., a compromised or vulnerable token), the exploit surface remains open. This is a **bypass of Cronos admin token-mapping authorization controls** (High impact per the allowed scope).

### Likelihood Explanation

`EnableAutoDeployment` is a module parameter that, when `true`, causes every new IBC token arrival to auto-deploy a CRC21 contract. Any denom that has ever received an IBC transfer while auto-deployment was enabled will have an auto contract. This is the common production path for IBC tokens on Cronos. An admin attempting to delist such a token via the only available mechanism (`MsgUpdateTokenMapping` with empty contract) will receive no error and believe the delist succeeded, while the auto contract path remains fully active.

### Recommendation

1. Add a `DeleteAutoContractForDenom` keeper method that removes both `DenomToAutoContractKey` and the corresponding `ContractToDenomKey` reverse entry.
2. In `RegisterOrUpdateTokenMapping`, when `msg.Contract` is empty, call both `DeleteExternalContractForDenom` and `DeleteAutoContractForDenom` so that the delist is complete regardless of which mapping type is active.
3. Return an explicit error (or at minimum a warning) if neither mapping existed when a delist is requested, so the admin is not silently misled.

### Proof of Concept

1. Deploy Cronos with `EnableAutoDeployment = true`.
2. Send an IBC transfer of denom `ibc/XXXX` to a Cronos address. The middleware auto-deploys a CRC21 contract (auto contract `B`) and sets `DenomToAutoContractKey[ibc/XXXX] = B`.
3. Admin registers an external contract `A` for the same denom via `MsgUpdateTokenMapping{Denom: "ibc/XXXX", Contract: "0xA..."}`. Now both mappings exist; `GetContractByDenom` returns `A` (external takes priority).
4. Admin delists by calling `MsgUpdateTokenMapping{Denom: "ibc/XXXX", Contract: ""}`. `DeleteExternalContractForDenom` removes `A` and re-establishes `ContractToDenomKey[B] = ibc/XXXX`. The call returns success.
5. Call `GetContractByDenom(ctx, "ibc/XXXX")` — it returns auto contract `B`, `found=true`.
6. Send another IBC transfer of `ibc/XXXX`. `canBeConverted` returns `true`; `OnRecvPacket` calls `ConvertVouchersToEvmCoins`; tokens are minted into the auto CRC21 contract — the delist had no effect.
7. Call `MsgTransferTokens` with `ibc/XXXX` — `IbcTransferCoins` finds the auto contract, passes the guard, and initiates the IBC transfer — the delist had no effect. [10](#0-9) [2](#0-1) [4](#0-3)

### Citations

**File:** x/cronos/keeper/keeper.go (L112-120)
```go
// GetContractByDenom find the corresponding contract for the denom,
// external contract is taken in preference to auto-deployed one
func (k Keeper) GetContractByDenom(ctx sdk.Context, denom string) (contract common.Address, found bool) {
	contract, found = k.getExternalContractByDenom(ctx, denom)
	if !found {
		contract, found = k.getAutoContractByDenom(ctx, denom)
	}
	return contract, found
}
```

**File:** x/cronos/keeper/keeper.go (L122-136)
```go
// GetDenomByContract find native denom by contract address
func (k Keeper) GetDenomByContract(ctx sdk.Context, contract common.Address) (denom string, found bool) {
	store := ctx.KVStore(k.storeKey)
	bz := store.Get(types.ContractToDenomKey(contract.Bytes()))
	if len(bz) == 0 {
		return "", false
	}
	denom = string(bz)
	// Cross-check against current mapping to avoid stale reverse entries in legacy state.
	current, ok := k.GetContractByDenom(ctx, denom)
	if !ok || current != contract {
		return "", false
	}
	return denom, true
}
```

**File:** x/cronos/keeper/keeper.go (L244-269)
```go
// DeleteExternalContractForDenom delete the external contract mapping for native denom,
// returns false if mapping not exists.
func (k Keeper) DeleteExternalContractForDenom(ctx sdk.Context, denom string) bool {
	store := ctx.KVStore(k.storeKey)
	contract, found := k.getExternalContractByDenom(ctx, denom)
	if !found {
		return false
	}
	store.Delete(types.DenomToExternalContractKey(denom))
	deleteReverseIfOwned(store, contract, denom)
	if auto, found := k.getAutoContractByDenom(ctx, denom); found {
		bz := store.Get(types.ContractToDenomKey(auto.Bytes()))
		if len(bz) == 0 {
			store.Set(types.ContractToDenomKey(auto.Bytes()), []byte(denom))
		} else if existingDenom := string(bz); existingDenom != denom {
			if k.contractOwnedByDenom(ctx, existingDenom, auto) {
				// auto address is already owned by another denom; drop local auto mapping
				store.Delete(types.DenomToAutoContractKey(denom))
			} else {
				// stale reverse entry
				store.Set(types.ContractToDenomKey(auto.Bytes()), []byte(denom))
			}
		}
	}
	return true
}
```

**File:** x/cronos/keeper/keeper.go (L384-401)
```go
	} else {
		if len(msg.Contract) == 0 {
			// delete existing mapping
			k.DeleteExternalContractForDenom(ctx, msg.Denom)
		} else {
			if !common.IsHexAddress(msg.Contract) {
				return errors.Wrapf(sdkerrors.ErrInvalidAddress, "invalid contract address (%s)", msg.Contract)
			}
			// update the mapping
			contract := common.HexToAddress(msg.Contract)
			if err := k.ensureContractCode(ctx, contract); err != nil {
				return err
			}
			if err := k.SetExternalContractForDenom(ctx, msg.Denom, contract); err != nil {
				return err
			}
		}
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

**File:** x/cronos/middleware/conversion_middleware.go (L256-263)
```go
func (im IBCConversionModule) canBeConverted(ctx sdk.Context, denom string) bool {
	params := im.cronoskeeper.GetParams(ctx)
	if denom == params.IbcCroDenom {
		return true
	}
	_, found := im.cronoskeeper.GetContractByDenom(ctx, denom)
	return found
}
```

**File:** x/cronos/keeper/ibc.go (L132-143)
```go
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
```

**File:** x/cronos/keeper/evmhandlers/send_to_ibc.go (L94-101)
```go
	denom, found := h.cronosKeeper.GetDenomByContract(ctx, contract)
	if !found {
		return fmt.Errorf("contract %s is not connected to native token", contract)
	}

	if !types.IsValidIBCDenom(denom) && !types.IsValidCronosDenom(denom) {
		return fmt.Errorf("the native token associated with the contract %s is neither an ibc voucher or a cronos token", contract)
	}
```

**File:** x/cronos/spec/03_state_transitions.md (L28-30)
```markdown
### Delete

There's no way to delete a token mapping currently.
```
