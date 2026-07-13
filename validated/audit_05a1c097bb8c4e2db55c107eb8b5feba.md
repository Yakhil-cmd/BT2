### Title
Source Denom (`cronos0x`) Token Mapping Is Permanently Immutable — Admin Cannot Remove a Vulnerable CRC21 Contract Mapping - (File: x/cronos/keeper/keeper.go)

### Summary

Once a `cronos0x...` source-denom token mapping is registered via `RegisterOrUpdateTokenMapping`, it is permanently locked. There is no code path to delete or update a source-denom mapping. If the mapped CRC21 contract is later found to be vulnerable, the admin cannot remove the mapping to stop an attacker from exploiting it to mint unbounded native tokens through the `SendToIbcHandler` EVM hook.

### Finding Description

`RegisterOrUpdateTokenMapping` in `x/cronos/keeper/keeper.go` branches on whether the denom is a source coin (`cronos0x...`):

- **Non-source denoms** (IBC, gravity): passing an empty `Contract` field calls `DeleteExternalContractForDenom`, allowing the admin to remove the mapping.
- **Source denoms**: the code unconditionally requires a valid hex address. If `msg.Contract` is empty, `common.IsHexAddress("")` returns `false` and the function returns `ErrInvalidAddress`. There is no deletion branch. [1](#0-0) 

Even if a non-empty address is supplied, `SetExternalContractForDenom` calls `ensureDenomNotMapped`, which returns `ErrDenomAlreadyMapped` for any denom that already has an active mapping. [2](#0-1) [3](#0-2) 

The module's own specification confirms this: **"There's no way to delete a token mapping currently."** [4](#0-3) 

The `SendToIbcHandler` EVM hook, triggered by any registered contract emitting `__CronosSendToIbc`, **mints** native tokens for source-denom contracts before initiating an IBC transfer: [5](#0-4) 

The handler only checks that the emitting contract is registered in the mapping — it does not verify that the caller is authorized: [6](#0-5) 

### Impact Explanation

If a source-denom CRC21 contract is mapped and later found to be exploitable (e.g., its `send_to_ibc` function is callable by anyone, or it has a reentrancy flaw), an unprivileged attacker can repeatedly trigger `__CronosSendToIbc` events. Each event causes `SendToIbcHandler` to **mint** native `cronos0x...` tokens from the module account and initiate IBC transfers, inflating the native token supply without authorization. Because the mapping cannot be removed, the admin has no on-chain mechanism to stop the drain. The `BlockAddressesDecorator` blocklist only runs in `CheckTx` (mempool), not in block execution, so it is not a reliable mitigation. [7](#0-6) 

**Impact class**: Critical — unauthorized mint of CRC21/native tokens; High — permanent bypass of admin token-mapping management authority.

### Likelihood Explanation

This requires the admin to have first mapped a source-denom contract that is later found to be vulnerable. While this is a precondition, it is a realistic operational scenario (contract upgrade bugs, newly discovered vulnerabilities). Once the mapping exists, the admin has zero on-chain recourse, making the window of exposure unbounded.

### Recommendation

Add a deletion path for source-denom mappings in `RegisterOrUpdateTokenMapping`. When `msg.Contract` is empty and `IsSourceCoin(msg.Denom)` is true, call `DeleteExternalContractForDenom` instead of returning `ErrInvalidAddress`. This mirrors the existing deletion logic for non-source denoms:

```go
if types.IsSourceCoin(msg.Denom) {
    if len(msg.Contract) == 0 {
        k.DeleteExternalContractForDenom(ctx, msg.Denom)
        return nil
    }
    // ... existing registration logic
}
``` [8](#0-7) 

### Proof of Concept

1. Admin calls `MsgUpdateTokenMapping` with `denom = "cronos0x<VulnerableContract>"`, `contract = "<VulnerableContract>"`. Mapping is stored.
2. A vulnerability is discovered in `VulnerableContract` — its `send_to_ibc(recipient, amount)` function is callable by any address.
3. Attacker calls `VulnerableContract.send_to_ibc(attacker_cosmos_addr, 1_000_000_000)`.
4. `VulnerableContract` emits `__CronosSendToIbc(attacker_evm_addr, attacker_cosmos_addr, 1_000_000_000)`.
5. `SendToIbcHandler.handle()` resolves the denom as a source coin, calls `bankKeeper.MintCoins(ModuleName, coins)`, sends coins to attacker, initiates IBC transfer.
6. Admin attempts to remove the mapping: `MsgUpdateTokenMapping{denom: "cronos0x<VulnerableContract>", contract: ""}`.
7. `RegisterOrUpdateTokenMapping` hits the source-coin branch, `common.IsHexAddress("") == false`, returns `ErrInvalidAddress`. Mapping remains.
8. Attacker repeats step 3 indefinitely, minting unbounded native tokens. [9](#0-8) [10](#0-9)

### Citations

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

**File:** x/cronos/keeper/keeper.go (L202-216)
```go
// SetExternalContractForDenom sets denom→external CRC21 mapping for an unmapped denom.
// Caller is responsible for source-denom specific validation before calling this method.
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
}
```

**File:** x/cronos/keeper/keeper.go (L330-404)
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
}
```

**File:** x/cronos/spec/03_state_transitions.md (L28-30)
```markdown
### Delete

There's no way to delete a token mapping currently.
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

**File:** x/cronos/keeper/evmhandlers/send_to_ibc.go (L109-123)
```go
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
```

**File:** app/block_address.go (L32-44)
```go
func (bad BlockAddressesDecorator) AnteHandle(ctx sdk.Context, tx sdk.Tx, simulate bool, next sdk.AnteHandler) (newCtx sdk.Context, err error) {
	if ctx.IsCheckTx() {
		if sigTx, ok := tx.(signing.SigVerifiableTx); ok {
			signers, err := sigTx.GetSigners()
			if err != nil {
				return ctx, err
			}
			for _, signer := range signers {
				if _, ok := bad.blockedMap[sdk.AccAddress(signer).String()]; ok {
					return ctx, fmt.Errorf("signer is blocked: %s", sdk.AccAddress(signer).String())
				}
			}
		}
```
