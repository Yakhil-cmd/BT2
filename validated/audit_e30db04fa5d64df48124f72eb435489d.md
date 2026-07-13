### Title
Admin Token-Mapping Update Permanently Blocked by Unprivileged Auto-Deployment Front-Run — (File: `x/cronos/keeper/keeper.go`)

---

### Summary

When `EnableAutoDeployment` is true, any unprivileged user can send an IBC transfer to Cronos to trigger auto-deployment of a CRC21 contract for a new denom. Once an auto-mapping exists for that denom, `SetExternalContractForDenom` reverts with `ErrDenomAlreadyMapped`. Because no message exists to delete an auto-mapping, the admin is permanently blocked from setting a custom external contract for that denom.

---

### Finding Description

**Root cause — `ensureDenomNotMapped` blocks both external and auto-mapped denoms:**

`SetExternalContractForDenom` unconditionally calls `ensureDenomNotMapped`, which calls `GetContractByDenom`. `GetContractByDenom` returns a hit for *either* an external or an auto-deployed mapping: [1](#0-0) [2](#0-1) 

So if an auto-mapping already exists for a denom, `SetExternalContractForDenom` returns `ErrDenomAlreadyMapped` and the entire `RegisterOrUpdateTokenMapping` call fails: [3](#0-2) 

**Unprivileged trigger path — IBC receive with auto-deployment enabled:**

`OnRecvVouchers` → `ConvertVouchersToEvmCoins` → `ConvertCoinFromNativeToCRC21(autoDeploy=params.EnableAutoDeployment)`. When no mapping exists and `autoDeploy` is true, a new CRC21 contract is deployed and `SetAutoContractForDenom` is called: [4](#0-3) 

This is triggered by any IBC packet received for a previously-unmapped denom — no admin permission required.

**No path to delete an auto-mapping:**

`DeleteExternalContractForDenom` only removes the *external* mapping key. It does not delete the auto-mapping key: [5](#0-4) 

`RegisterOrUpdateTokenMapping` with an empty contract calls `DeleteExternalContractForDenom`, which returns `false` (no-op) when only an auto-mapping exists: [6](#0-5) 

There is no `MsgDeleteAutoContractForDenom` or equivalent. The admin has no on-chain message path to remove an auto-mapping.

---

### Impact Explanation

**High — Bypass of Cronos admin token-mapping authority.**

The admin (or any `CanChangeTokenMapping`-permissioned address) is permanently unable to register a custom external contract for any denom that an attacker has pre-seeded with an auto-deployment. This directly matches the allowed High impact: *"Bypass of Cronos admin… token-mapping… authorization checks"* and *"Permanent or long-lived inability… to process valid… bridge/conversion flows… under normal network assumptions."*

Concrete consequences:
- The admin cannot replace an auto-deployed CRC21 with an audited, feature-rich external contract (e.g., one with a blocklist or rate-limiting).
- The governance `TokenMappingChangeProposal` path calls the same `RegisterOrUpdateTokenMapping` and is equally blocked.
- Recovery requires a chain upgrade or a bespoke governance proposal that directly manipulates KV store state — extraordinary measures outside normal operations.

---

### Likelihood Explanation

Moderate. Preconditions:
1. `EnableAutoDeployment` is `true` (the default/common Cronos configuration).
2. The attacker holds any amount of the target IBC or gravity denom on the source chain.
3. The attacker sends an IBC transfer to Cronos before the admin's `MsgUpdateTokenMapping` is included in a block.

No front-running is strictly required: the attacker can proactively seed auto-mappings for any denom they anticipate the admin will want to map, at any time before the admin acts.

---

### Recommendation

In `SetExternalContractForDenom` (or in `RegisterOrUpdateTokenMapping` before calling it), when an **auto-mapping** (but not an external mapping) already exists for the denom, delete the auto-mapping entry and proceed with writing the external mapping, rather than reverting. This mirrors the fix suggested in the reference report: perform the necessary cleanup instead of reverting.

Alternatively, expose a privileged `MsgDeleteAutoContractForDenom` message (restricted to `CanChangeTokenMapping`) so the admin can clear a stale auto-mapping before registering an external one.

---

### Proof of Concept

```
Precondition: EnableAutoDeployment = true, denom "ibc/XXXX" has no mapping.

Step 1 — Attacker sends 1 ibc/XXXX token via IBC to any Cronos address.

Step 2 — IBC middleware calls OnRecvVouchers(["ibc/XXXX:1"], receiver)
         → ConvertVouchersToEvmCoins
         → ConvertCoinFromNativeToCRC21(coin="ibc/XXXX:1", autoDeploy=true)
         → DeployModuleCRC21("ibc/XXXX") → contract 0xAUTO
         → SetAutoContractForDenom("ibc/XXXX", 0xAUTO)   ✓ succeeds

Step 3 — Admin submits MsgUpdateTokenMapping{Denom:"ibc/XXXX", Contract:"0xCUSTOM"}
         → RegisterOrUpdateTokenMapping
         → SetExternalContractForDenom("ibc/XXXX", 0xCUSTOM)
         → ensureDenomNotMapped("ibc/XXXX")
         → GetContractByDenom returns (0xAUTO, true)
         → returns ErrDenomAlreadyMapped  ✗ REVERTS

Step 4 — Admin tries MsgUpdateTokenMapping{Denom:"ibc/XXXX", Contract:""}
         → DeleteExternalContractForDenom("ibc/XXXX")
         → getExternalContractByDenom returns (_, false)
         → returns false (no-op)          ✗ Auto-mapping untouched

Result: 0xAUTO is permanently the only contract for "ibc/XXXX".
        Admin's intended 0xCUSTOM mapping is permanently blocked.
```

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

**File:** x/cronos/keeper/evm.go (L91-111)
```go
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
```
