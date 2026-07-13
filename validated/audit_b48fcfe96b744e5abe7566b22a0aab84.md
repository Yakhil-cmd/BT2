### Title
Source-coin (`cronos0x`) token mappings are permanently irremovable, locking compromised contracts into the conversion path — (`x/cronos/keeper/keeper.go`, `x/cronos/types/proposal.go`)

---

### Summary

`RegisterOrUpdateTokenMapping` in the Cronos keeper provides a deletion path for non-source (IBC/gravity) denoms but has no deletion path for source-coin (`cronos0x`) denoms. Once a `cronos0x{contractAddr}` mapping is registered, neither the Cronos admin nor governance can ever remove it. If the mapped contract is later modified to be malicious, the module will continue routing native-token burns through it with no recourse.

---

### Finding Description

`RegisterOrUpdateTokenMapping` branches on `types.IsSourceCoin(msg.Denom)`:

- **Non-source branch** (IBC, gravity): an empty `msg.Contract` triggers `DeleteExternalContractForDenom`, allowing the admin to remove the mapping at any time.
- **Source-coin branch** (`cronos0x`): the code unconditionally requires a valid hex contract address and calls `SetExternalContractForDenom`. There is no empty-contract deletion path. [1](#0-0) 

`SetExternalContractForDenom` itself calls `ensureDenomNotMapped`, which returns `ErrDenomAlreadyMapped` if the denom already has an active mapping. Because there is no deletion path for source coins, this guard makes the mapping permanently immutable after first registration. [2](#0-1) 

The governance path (`TokenMappingChangeProposal` → `NewTokenMappingChangeProposalHandler`) routes through the same `RegisterOrUpdateTokenMapping`, so governance cannot delete source-coin mappings either. [3](#0-2) 

`ValidateBasic` for `TokenMappingChangeProposal` explicitly rejects an empty contract for source denoms, closing the governance deletion path at the validation layer: [4](#0-3) 

The spec itself acknowledges this: *"There's no way to delete a token mapping currently."* [5](#0-4) 

---

### Impact Explanation

When `ConvertCoinFromNativeToCRC21` processes a source coin, it:
1. Burns the user's native `cronos0x` tokens from the bank module.
2. Calls `transfer_from_cronos_module` on the mapped contract to release EVM tokens to the user. [6](#0-5) 

If the mapped contract is later modified so that `transfer_from_cronos_module` silently succeeds without transferring tokens (or transfers them to an attacker-controlled address), the user's native tokens are burned and they receive nothing. Because the mapping cannot be removed, the Cronos admin has no mechanism to halt this drain. Every subsequent conversion call for that denom results in an unauthorized burn of native tokens with no corresponding EVM token issuance — a permanent accounting corruption for all holders of that `cronos0x` denom.

---

### Likelihood Explanation

The contract owner (who is not the Cronos admin and holds no Cronos module privileges) can upgrade or modify the contract's `transfer_from_cronos_module` implementation at any time after registration. The Cronos admin, despite controlling all other token-mapping operations, has no on-chain mechanism to remove the source-coin mapping and stop the damage. The asymmetry is structural: non-source mappings are deletable; source-coin mappings are not.

---

### Recommendation

In `RegisterOrUpdateTokenMapping`, add a deletion branch for source coins when `msg.Contract` is empty, mirroring the non-source branch:

```go
if types.IsSourceCoin(msg.Denom) {
    if len(msg.Contract) == 0 {
        k.DeleteExternalContractForDenom(ctx, msg.Denom)
        return nil
    }
    // ... existing registration logic
}
```

Remove the `ValidateBasic` restriction that rejects empty contracts for source denoms in `TokenMappingChangeProposal`, so governance can also trigger deletion. [4](#0-3) 

---

### Proof of Concept

1. Cronos admin calls `MsgUpdateTokenMapping` with `denom = "cronos0x<contractAddr>"`, `contract = "<contractAddr>"`. Mapping is registered.
2. Admin attempts to remove it by calling `MsgUpdateTokenMapping` with `denom = "cronos0x<contractAddr>"`, `contract = ""`. The source-coin branch requires a valid hex address — the call is rejected with `ErrInvalidAddress`.
3. Admin attempts governance removal via `TokenMappingChangeProposal` with empty contract. `ValidateBasic` rejects it: *"invalid contract address for source denom"*.
4. Contract owner upgrades the contract so `transfer_from_cronos_module` emits a success event but transfers tokens to the attacker instead of the caller.
5. Any user calling `MsgConvertVouchers` with `cronos0x<contractAddr>` coins has their native tokens burned (step confirmed by `BurnCoins` at `evm.go:121`) and receives no EVM tokens. The admin cannot stop this. [7](#0-6) [8](#0-7)

### Citations

**File:** x/cronos/keeper/keeper.go (L172-181)
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
```

**File:** x/cronos/keeper/keeper.go (L330-403)
```go
func (k Keeper) RegisterOrUpdateTokenMapping(ctx sdk.Context, msg *types.MsgUpdateTokenMapping) error {
	if types.IsSourceCoin(msg.Denom) {
		_, err := types.GetContractAddressFromDenom(msg.Denom)
		if err != nil {
			return err
		}

		if !common.IsHexAddress(msg.Contract) {
			return errors.Wrapf(sdkerrors.ErrInvalidAddress, "invalid contract address (%s)", msg.Contract)
		}
		contract := common.HexToAddress(msg.Contract)
		if err := k.ensureContractCode(ctx, contract); err != nil {
			return err
		}
		if err := validateContractAddressForSourceDenom(msg.Denom, contract, true); err != nil {
			return err
		}

		if err := k.SetExternalContractForDenom(ctx, msg.Denom, contract); err != nil {
			return err
		}

		// check that the coin is registered, otherwise register it
		metadata, exist := k.bankKeeper.GetDenomMetaData(ctx, msg.Denom)
		if !exist {
			// create new metadata
			metadata = banktypes.Metadata{
				Base: msg.Denom,
				Name: msg.Denom,
			}
		}
		// update existing metadata
		metadata.Symbol = msg.Symbol
		metadata.Display = strings.ToLower(msg.Symbol)
		if msg.Decimal != 0 {
			metadata.DenomUnits = []*banktypes.DenomUnit{
				{
					Denom:    metadata.Base,
					Exponent: 0,
				},
				{
					Denom:    metadata.Display,
					Exponent: msg.Decimal,
				},
			}
		} else {
			metadata.DenomUnits = []*banktypes.DenomUnit{
				{
					Denom:    metadata.Base,
					Exponent: 0,
				},
			}
		}
		k.bankKeeper.SetDenomMetaData(ctx, metadata)
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

	return nil
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

**File:** x/cronos/types/proposal.go (L54-64)
```go
	if IsSourceCoin(tcp.Denom) {
		// source-denom mappings always require a valid contract address
		if !common.IsHexAddress(tcp.Contract) {
			return fmt.Errorf("invalid contract address for source denom: %s", tcp.Contract)
		}
	} else {
		// non-source mappings allow empty contract (delete) or a valid hex address
		if len(tcp.Contract) > 0 && !common.IsHexAddress(tcp.Contract) {
			return fmt.Errorf("invalid contract address: %s", tcp.Contract)
		}
	}
```

**File:** x/cronos/spec/03_state_transitions.md (L28-30)
```markdown
### Delete

There's no way to delete a token mapping currently.
```

**File:** x/cronos/keeper/evm.go (L113-130)
```go
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
```
