### Title
Irremovable `cronos0x` Source-Denom Token Mapping — No On-Chain Path to Delete or Pause a Registered Source-Denom Binding — (File: `x/cronos/keeper/keeper.go`)

---

### Summary

Once a `cronos0x` source-denom is mapped to a CRC21 contract via `MsgUpdateTokenMapping` or `TokenMappingChangeProposal`, neither the Cronos admin nor governance can ever remove or replace that mapping. The `RegisterOrUpdateTokenMapping` function has no delete path for source coins, and `TokenMappingChangeProposal.ValidateBasic()` explicitly rejects an empty contract address for source denoms. The low-level `DeleteExternalContractForDenom` keeper function exists but is unreachable through any on-chain message or proposal for source denoms. If the bound CRC21 contract is later found to be buggy or compromised, governance has no emergency mechanism to disconnect it from the native-denom bridge.

---

### Finding Description

**Root cause — `RegisterOrUpdateTokenMapping` has no delete branch for source coins:**

```go
func (k Keeper) RegisterOrUpdateTokenMapping(ctx sdk.Context, msg *types.MsgUpdateTokenMapping) error {
    if types.IsSourceCoin(msg.Denom) {          // cronos0x... path
        // ... validation ...
        if err := k.SetExternalContractForDenom(ctx, msg.Denom, contract); err != nil {
            return err                           // ErrDenomAlreadyMapped if already set
        }
        // no delete branch exists here
    } else {
        if len(msg.Contract) == 0 {
            k.DeleteExternalContractForDenom(ctx, msg.Denom)  // delete only for non-source
        } else { ... }
    }
    return nil
}
``` [1](#0-0) 

The `else` branch (non-source denoms: `ibc/`, `gravity0x`) allows deletion by passing an empty `Contract` field. The source-coin branch has no equivalent path.

**`SetExternalContractForDenom` enforces create-only semantics:**

```go
func (k Keeper) SetExternalContractForDenom(ctx sdk.Context, denom string, address common.Address) error {
    if err := k.ensureDenomNotMapped(ctx, denom); err != nil {
        return err   // ErrDenomAlreadyMapped — rejects any re-registration
    }
    ...
}
``` [2](#0-1) [3](#0-2) 

**`TokenMappingChangeProposal.ValidateBasic()` blocks governance from passing an empty contract for source denoms:**

```go
if IsSourceCoin(tcp.Denom) {
    // source-denom mappings always require a valid contract address
    if !common.IsHexAddress(tcp.Contract) {
        return fmt.Errorf("invalid contract address for source denom: %s", tcp.Contract)
    }
}
``` [4](#0-3) 

This means the governance proposal path also cannot delete a source-denom mapping.

**The spec explicitly acknowledges the gap:**

> "There's no way to delete a token mapping currently." [5](#0-4) 

**`DeleteExternalContractForDenom` exists but is unreachable for source denoms via any message:**

The function is a keeper-internal primitive. No `MsgUpdateTokenMapping` handler, no `TokenMappingChangeProposal` handler, and no other on-chain message routes to it for `cronos0x` denoms. [6](#0-5) 

---

### Impact Explanation

A `cronos0x` source-denom mapping binds a native Cosmos denom to a CRC21 contract. The `BurnVouchersToEvmCoins` flow burns native tokens and calls `mint_by_cronos_module` on the bound CRC21 contract. If the bound contract is later found to be buggy or compromised (e.g., it mints more than the burned amount, or has a reentrancy path), governance has no on-chain mechanism to disconnect the mapping and halt the damage. The mapping is permanent until a chain upgrade.

This matches the **High** impact category: **Permanent or long-lived inability for governance/admin to exercise authority over token-mapping and bridge/conversion flows**, and **Corruption of denom/contract binding state with direct security impact** if the bound contract misbehaves. [7](#0-6) 

---

### Likelihood Explanation

The scenario requires:
1. An unprivileged user deploys a CRC21 contract (permissionless).
2. The Cronos admin or governance approves a `cronos0x` source-denom mapping for it — a legitimate action analogous to Frankencoin governance approving a minter after the 10-day window.
3. A bug or compromise in the CRC21 contract is discovered post-registration.
4. Governance attempts to remove the mapping and finds no on-chain path to do so.

This is the exact structural analog to the Frankencoin M-13 finding: a privileged actor (minter / source-denom contract) is approved through governance and then becomes irremovable. The ADR-008 changelog entry dated 2026-04-29 explicitly tightened source-denom immutability, making this a deliberate design choice with no corresponding emergency-removal mechanism. [8](#0-7) 

---

### Recommendation

1. Add a delete path for source-denom mappings in `RegisterOrUpdateTokenMapping`: when `msg.Contract` is empty and `IsSourceCoin(msg.Denom)`, call `DeleteExternalContractForDenom`.
2. Remove the `ValidateBasic()` restriction that rejects empty contract for source denoms in `TokenMappingChangeProposal`, or add a separate `TokenMappingDeleteProposal` type.
3. Consider a time-locked or governance-gated pause mechanism for source-denom bridge flows, analogous to the `TurnBridge` mechanism that already exists for the gravity bridge. [9](#0-8) [10](#0-9) 

---

### Proof of Concept

1. Deploy a CRC21 contract `0xDEAD...` on Cronos EVM.
2. Admin submits `MsgUpdateTokenMapping{Denom: "cronos0x<DEAD...>", Contract: "0xDEAD..."}`. Mapping is created.
3. A bug is discovered in `0xDEAD...` that allows it to mint unbounded tokens when `mint_by_cronos_module` is called.
4. Admin attempts to remove the mapping: `MsgUpdateTokenMapping{Denom: "cronos0x<DEAD...>", Contract: ""}` — **rejected** because `IsSourceCoin` is true and the code path has no delete branch; `SetExternalContractForDenom` returns `ErrDenomAlreadyMapped`.
5. Governance submits `TokenMappingChangeProposal{Denom: "cronos0x<DEAD...>", Contract: ""}` — **rejected** at `ValidateBasic()` with `"invalid contract address for source denom"`.
6. The mapping remains active permanently. Every `BurnVouchersToEvmCoins` call continues to invoke `mint_by_cronos_module` on the compromised contract with no on-chain recourse. [11](#0-10) [12](#0-11)

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

**File:** x/cronos/keeper/keeper.go (L244-268)
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

**File:** x/cronos/types/proposal.go (L44-67)
```go
// ValidateBasic validates the parameter change proposal
func (tcp *TokenMappingChangeProposal) ValidateBasic() error {
	if err := govtypes.ValidateAbstract(tcp); err != nil {
		return err
	}

	if !IsValidCoinDenom(tcp.Denom) {
		return fmt.Errorf("invalid coin denom: %s", tcp.Denom)
	}

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

	return nil
}
```

**File:** x/cronos/spec/03_state_transitions.md (L28-30)
```markdown
### Delete

There's no way to delete a token mapping currently.
```

**File:** x/cronos/types/types.go (L40-43)
```go
// IsSourceCoin returns true if denom is a coin originated from cronos
func IsSourceCoin(denom string) bool {
	return IsValidCronosDenom(denom)
}
```

**File:** docs/architecture/adr-008.md (L74-89)
```markdown
#### Current implementation notes (2026-04)

The following guardrails are now enforced in keeper implementation:

1. **Create-only mapping for mapped denoms**  
   A denom that already resolves to an active contract is rejected for re-registration (`ErrDenomAlreadyMapped`), instead of being silently remapped.

2. **1-to-1 mapping remains enforced in both directions**  
   A contract already actively owned by another denom is rejected (`ErrContractAlreadyRegistered`).

3. **Source-denom contract consistency is validated at registration boundary**  
   For source denoms (`cronos0x...`), `RegisterOrUpdateTokenMapping` validates that requested contract address matches the contract encoded in denom (`ErrSourceDenomContractMismatch`).

4. **Setter boundary is explicit**  
   `SetExternalContractForDenom` acts as a low-level mapping write primitive (caller validates source-denom semantics before calling).  
   `SetAutoContractForDenom` enforces source-denom contract consistency directly to avoid bypass through auto-mapping path.
```
