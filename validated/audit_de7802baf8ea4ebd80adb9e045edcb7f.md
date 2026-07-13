### Title
Unprivileged Actor Can Permanently Block Admin External Token-Mapping Registration via Auto-Deploy Front-Running — (File: x/cronos/keeper/evm.go)

---

### Summary

When `EnableAutoDeployment=true`, any unprivileged user holding IBC tokens can call `MsgConvertVouchers` to trigger auto-deployment of a CRC21 contract for a previously-unmapped IBC denom. Once the auto contract is written to state, `SetExternalContractForDenom` permanently fails with `ErrDenomAlreadyMapped` for that denom, and there is no keeper function to remove an auto contract mapping. This permanently blocks the Cronos admin from registering their intended external contract via `MsgUpdateTokenMapping`, bypassing admin token-mapping authority.

---

### Finding Description

**Root cause — `ConvertCoinFromNativeToCRC21` auto-deploys and locks the denom mapping:** [1](#0-0) 

When `autoDeploy=true` (controlled by the `EnableAutoDeployment` param) and no contract is found for the denom, the function deploys a new `ModuleCRC21` contract and calls `SetAutoContractForDenom`. This path is reachable by any user via `MsgConvertVouchers`: [2](#0-1) 

which calls `ConvertVouchersToEvmCoins` passing `params.EnableAutoDeployment` as the `autoDeploy` flag: [3](#0-2) 

**The lock — `SetExternalContractForDenom` is blocked by `ensureDenomNotMapped`:**

`SetExternalContractForDenom`, called by `RegisterOrUpdateTokenMapping` (the admin's `MsgUpdateTokenMapping` handler), unconditionally calls `ensureDenomNotMapped` first: [4](#0-3) 

`ensureDenomNotMapped` calls `GetContractByDenom`, which returns the auto contract if no external contract is set: [5](#0-4) [6](#0-5) 

So if an auto contract is already registered for the denom, `ensureDenomNotMapped` returns `ErrDenomAlreadyMapped` and the admin's `MsgUpdateTokenMapping` fails.

**The permanence — no `DeleteAutoContractForDenom` exists:**

`DeleteExternalContractForDenom` only removes external contract entries: [7](#0-6) 

There is no corresponding function to delete an auto contract mapping. The ADR-008 (2026-04 notes) explicitly documents this as a "create-only" guardrail: [8](#0-7) 

Once an auto contract is set for a denom, the admin has no on-chain mechanism to clear it and register their preferred external contract.

**Attack path:**

1. Governance enables `EnableAutoDeployment=true`.
2. Admin prepares a `MsgUpdateTokenMapping` to register a specific external CRC21 contract for a new IBC denom (e.g., `ibc/XXXX`).
3. Attacker, holding any amount of `ibc/XXXX` tokens, submits `MsgConvertVouchers` with that denom before the admin's transaction is included.
4. `ConvertCoinFromNativeToCRC21` deploys a `ModuleCRC21` contract and calls `SetAutoContractForDenom`, writing the auto mapping to state.
5. Admin's `MsgUpdateTokenMapping` is processed: `SetExternalContractForDenom` → `ensureDenomNotMapped` → `ErrDenomAlreadyMapped` → transaction fails.
6. The admin is permanently blocked from registering their intended external contract for that denom.

---

### Impact Explanation

**High** — Permanent bypass of Cronos admin token-mapping authority. The admin cannot register their preferred external CRC21 contract for any IBC denom that an attacker has pre-empted with an auto-deploy. This corrupts the intended denom/contract binding with direct security impact: the admin's chosen contract (which may have different supply management, access controls, or integration properties) can never be activated for that denom. There is no on-chain recovery path without a chain upgrade.

---

### Likelihood Explanation

Requires `EnableAutoDeployment=true` (a governance-controlled parameter, not the default) and the attacker holding any nonzero amount of the target IBC token. Both conditions are realistic in a live network where auto-deployment is enabled to support seamless IBC token wrapping. The attacker only needs to submit a single `MsgConvertVouchers` transaction before the admin's `MsgUpdateTokenMapping`.

---

### Recommendation

One of the following mitigations should be applied:

1. **Allow admin override of auto mappings:** Modify `SetExternalContractForDenom` (or `RegisterOrUpdateTokenMapping`) to permit the admin to replace an existing auto contract mapping with an external one, rather than unconditionally rejecting with `ErrDenomAlreadyMapped` when an auto contract exists.

2. **Add `DeleteAutoContractForDenom` for admin use:** Expose a privileged keeper function (callable only by the admin or governance) to remove an auto contract mapping, allowing the admin to clear it before registering their external contract.

3. **Restrict `MsgConvertVouchers` auto-deploy to already-mapped denoms:** Prevent `ConvertCoinFromNativeToCRC21` from auto-deploying a contract for a denom that has never been explicitly registered, reserving first-time mapping exclusively for the admin.

---

### Proof of Concept

```
// Precondition: EnableAutoDeployment = true
// Attacker holds 1 ibc/XXXX token

// Step 1: Attacker front-runs admin by calling MsgConvertVouchers
MsgConvertVouchers{
    Address: attacker_address,
    Coins:   [{ Denom: "ibc/XXXX", Amount: 1 }],
}
// → ConvertVouchersToEvmCoins → ConvertCoinFromNativeToCRC21(autoDeploy=true)
// → DeployModuleCRC21 → SetAutoContractForDenom("ibc/XXXX", auto_contract_addr)
// State: DenomToAutoContract["ibc/XXXX"] = auto_contract_addr ✓

// Step 2: Admin submits MsgUpdateTokenMapping
MsgUpdateTokenMapping{
    Denom:    "ibc/XXXX",
    Contract: "0xAdminPreferredContract",
}
// → RegisterOrUpdateTokenMapping → SetExternalContractForDenom
// → ensureDenomNotMapped → GetContractByDenom returns auto_contract_addr
// → ErrDenomAlreadyMapped: "denom ibc/XXXX is already mapped to contract <auto_contract_addr>"
// Admin tx FAILS permanently. No recovery path.
```

### Citations

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

**File:** x/cronos/keeper/msg_server.go (L27-44)
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
```

**File:** x/cronos/keeper/ibc.go (L59-64)
```go
		default:
			err := k.ConvertCoinFromNativeToCRC21(ctx, common.BytesToAddress(acc.Bytes()), c, params.EnableAutoDeployment)
			if err != nil {
				return err
			}
		}
```

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
