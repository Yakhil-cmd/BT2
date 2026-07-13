### Title
Unprivileged IBC Transfer Front-Runs Governance `TokenMappingChangeProposal`, Permanently Blocking External Contract Registration - (File: `x/cronos/keeper/evm.go`, `x/cronos/keeper/keeper.go`, `x/cronos/middleware/conversion_middleware.go`)

---

### Summary

When `EnableAutoDeployment` is `true`, any unprivileged user can send a small IBC transfer of a target denom to Cronos, triggering auto-deployment of a basic CRC21 contract for that denom. Because `SetExternalContractForDenom` enforces a strict create-only guard (`ensureDenomNotMapped`), a subsequent governance `TokenMappingChangeProposal` attempting to register a specific external contract for the same denom will permanently fail with `ErrDenomAlreadyMapped`. There is no governance path to override or delete an auto-deployed mapping.

---

### Finding Description

**Auto-deployment path** (`x/cronos/keeper/evm.go`, `ConvertCoinFromNativeToCRC21`):

When `EnableAutoDeployment` is `true` and an IBC token arrives for a denom with no existing mapping, the IBC conversion middleware calls `ConvertVouchersToEvmCoins` → `ConvertCoinFromNativeToCRC21` with `autoDeploy=true`. This deploys a new `ModuleCRC21` contract and registers it via `SetAutoContractForDenom`. [1](#0-0) 

**Create-only guard** (`x/cronos/keeper/keeper.go`, `ensureDenomNotMapped`):

Both `SetExternalContractForDenom` and `SetAutoContractForDenom` call `ensureDenomNotMapped`, which checks both the external and auto-contract mappings via `GetContractByDenom`. If either mapping exists, it returns `ErrDenomAlreadyMapped` unconditionally. [2](#0-1) [3](#0-2) 

**Governance handler** (`x/cronos/proposal_handler.go`):

`NewTokenMappingChangeProposalHandler` calls `RegisterOrUpdateTokenMapping`, which for non-source denoms calls `SetExternalContractForDenom`. This hits `ensureDenomNotMapped` and fails if the denom was already auto-mapped. [4](#0-3) [5](#0-4) 

**No override path exists**: `DeleteExternalContractForDenom` only removes the external mapping, not the auto-deployed mapping. There is no governance message to delete or override an auto-deployed contract mapping. [6](#0-5) 

**IBC middleware trigger** (`x/cronos/middleware/conversion_middleware.go`):

`OnRecvPacket` calls `ConvertVouchersToEvmCoins` for any denom that `canBeConverted` returns true for. For a new denom with no mapping and `EnableAutoDeployment=true`, this triggers auto-deployment. [7](#0-6) 

---

### Impact Explanation

Once an attacker triggers auto-deployment for a target denom, governance can never register a different external contract for that denom. The denom is permanently bound to the auto-deployed basic `ModuleCRC21` contract. If governance intended to map the denom to a feature-rich external CRC21/CRC20 contract (e.g., one with specific bridge permissions, proxy logic, or supply controls), that mapping is permanently blocked. This constitutes:

- **Bypass of governance authority**: A passed governance proposal fails to execute.
- **Corruption of token mappings**: The denom is bound to an unintended contract with no recovery path through governance.
- **Long-lived inability** for governance to correct the token mapping, affecting all future bridge/conversion flows for that denom.

---

### Likelihood Explanation

- `EnableAutoDeployment` is a live chain parameter that can be enabled via governance and is used in production for IBC token auto-wrapping.
- Any user who can send an IBC transfer of the target denom to Cronos (i.e., any holder of that token on the source chain) can trigger the attack.
- The attack window is the entire governance voting period (days), making front-running trivial — no mempool racing is required.
- The attacker only needs to send a minimal amount (1 unit) of the target IBC token.

---

### Recommendation

1. **Short term**: In `RegisterOrUpdateTokenMapping` (and the governance handler), allow governance to override an existing auto-deployed mapping with an external contract. The auto-deployed mapping should be treated as a lower-priority fallback, not a permanent lock.

2. **Long term**: Separate the "create-only" guard for external-to-external remapping (which is intentional per ADR-008) from the "auto-to-external upgrade" path. Governance should always be able to promote an auto-deployed mapping to an explicit external contract mapping, since auto-deployment is a best-effort fallback, not an authoritative registration.

---

### Proof of Concept

1. Governance submits a `TokenMappingChangeProposal` to map `ibc/XXXX` → `0xExternalContract` (voting period begins, e.g., 7 days).
2. Attacker sends 1 unit of `ibc/XXXX` from the source chain to any Cronos address while `EnableAutoDeployment=true`.
3. `IBCConversionModule.OnRecvPacket` → `ConvertVouchersToEvmCoins` → `ConvertCoinFromNativeToCRC21(autoDeploy=true)` → `DeployModuleCRC21` → `SetAutoContractForDenom` registers `ibc/XXXX` → `0xAutoDeployedCRC21`.
4. Governance proposal passes and executes: `NewTokenMappingChangeProposalHandler` → `RegisterOrUpdateTokenMapping` → `SetExternalContractForDenom` → `ensureDenomNotMapped` → returns `ErrDenomAlreadyMapped: denom ibc/XXXX is already mapped to contract 0xAutoDeployedCRC21`.
5. The governance proposal fails. `ibc/XXXX` remains permanently mapped to the auto-deployed basic contract. No governance path exists to override it. [8](#0-7) [9](#0-8)

### Citations

**File:** x/cronos/keeper/evm.go (L71-88)
```go
func (k Keeper) DeployModuleCRC21(ctx sdk.Context, denom string) (common.Address, error) {
	ctor, err := types.ModuleCRC21Contract.ABI.Pack("", denom, uint8(0), false)
	if err != nil {
		return common.Address{}, err
	}
	data := types.ModuleCRC21Contract.Bin
	data = append(data, ctor...)

	msg, res, err := k.CallEVM(ctx, nil, data, big.NewInt(0), DefaultGasCap)
	if err != nil {
		return common.Address{}, err
	}

	if res.Failed() {
		return common.Address{}, fmt.Errorf("contract deploy failed: %s", res.Ret)
	}
	return crypto.CreateAddress(types.EVMModuleAddress, msg.Nonce), nil
}
```

**File:** x/cronos/keeper/evm.go (L97-110)
```go
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
```

**File:** x/cronos/keeper/keeper.go (L172-182)
```go
func (k Keeper) ensureDenomNotMapped(ctx sdk.Context, denom string) error {
	if contract, found := k.GetContractByDenom(ctx, denom); found {
		return errors.Wrapf(
			types.ErrDenomAlreadyMapped,
			"denom %s is already mapped to contract %s",
			denom,
			contract.Hex(),
		)
	}
	return nil
}
```

**File:** x/cronos/keeper/keeper.go (L204-215)
```go
func (k Keeper) SetExternalContractForDenom(ctx sdk.Context, denom string, address common.Address) error {
	if err := k.ensureDenomNotMapped(ctx, denom); err != nil {
		return err
	}
	if err := k.ensureContractNotMapped(ctx, denom, address); err != nil {
		return err
	}

	store := ctx.KVStore(k.storeKey)
	store.Set(types.DenomToExternalContractKey(denom), address.Bytes())
	store.Set(types.ContractToDenomKey(address.Bytes()), []byte(denom))
	return nil
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

**File:** x/cronos/keeper/keeper.go (L271-287)
```go
// SetAutoContractForDenom set the auto deployed contract for native denom
func (k Keeper) SetAutoContractForDenom(ctx sdk.Context, denom string, address common.Address) error {
	isSource := types.IsSourceCoin(denom)
	if err := validateContractAddressForSourceDenom(denom, address, isSource); err != nil {
		return err
	}
	if err := k.ensureDenomNotMapped(ctx, denom); err != nil {
		return err
	}
	if err := k.ensureContractNotMapped(ctx, denom, address); err != nil {
		return err
	}
	store := ctx.KVStore(k.storeKey)
	store.Set(types.DenomToAutoContractKey(denom), address.Bytes())
	store.Set(types.ContractToDenomKey(address.Bytes()), []byte(denom))
	return nil
}
```

**File:** x/cronos/keeper/keeper.go (L384-400)
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
```

**File:** x/cronos/proposal_handler.go (L15-33)
```go
func NewTokenMappingChangeProposalHandler(k keeper.Keeper) govtypes.Handler {
	return func(ctx sdk.Context, content govtypes.Content) error {
		switch c := content.(type) {
		case *types.TokenMappingChangeProposal:
			if err := c.ValidateBasic(); err != nil {
				return err
			}

			msg := types.MsgUpdateTokenMapping{
				Denom:    c.Denom,
				Contract: c.Contract,
				Symbol:   c.Symbol,
				Decimal:  c.Decimal,
			}
			return k.RegisterOrUpdateTokenMapping(ctx, &msg)
		default:
			return errors.Wrapf(sdkerrors.ErrUnknownRequest, "unrecognized cronos proposal content type: %T", c)
		}
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
