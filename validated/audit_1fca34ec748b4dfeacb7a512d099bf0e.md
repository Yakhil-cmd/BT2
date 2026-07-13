### Title
Genesis Round-Trip Silently Drops All `AdminToPermissions` State, Permanently Revoking Delegated Permissions After Chain Upgrade — (`x/cronos/genesis.go`, `x/cronos/types/genesis.pb.go`)

---

### Summary

`ExportGenesis` never serializes the `KeyPrefixAdminToPermissions` KV entries, and `InitGenesis` never restores them. Every address granted `CanChangeTokenMapping` or `CanTurnBridge` via `SetPermissions` silently loses those permissions after any genesis export-import (i.e., every chain upgrade). The loss is permanent until governance or the admin re-grants each permission individually.

---

### Finding Description

`SetPermissions` writes address→uint64 entries under `KeyPrefixAdminToPermissions`: [1](#0-0) 

The `GenesisState` protobuf struct has exactly three fields — `Params`, `ExternalContracts`, `AutoContracts` — with no field for permissions: [2](#0-1) 

`ExportGenesis` only populates those three fields: [3](#0-2) 

`InitGenesis` only restores those three fields: [4](#0-3) 

There is no `GetAllPermissions`, `IteratePermissions`, or equivalent keeper method anywhere in the module — confirmed by the absence of any such symbol in `x/cronos/keeper/`. The `KeyPrefixAdminToPermissions` key prefix is defined but never iterated for export: [5](#0-4) 

---

### Impact Explanation

After any chain upgrade (which performs an export-import cycle), every address previously granted `CanChangeTokenMapping` or `CanTurnBridge` has `GetPermissions` return `0`. `HasPermission` then falls through to the `CronosAdmin` check only, so all delegated operators permanently lose the ability to call `MsgUpdateTokenMapping` and `MsgTurnBridge`. Token mapping updates and bridge control are blocked until governance or the admin manually re-grants each permission — a permanent, silent regression on every upgrade. [6](#0-5) 

---

### Likelihood Explanation

Every chain upgrade triggers a genesis export-import. The permissions are silently dropped with no error, no log, and no panic. The regression is only discovered when a permissioned operator attempts a `MsgUpdateTokenMapping` or `MsgTurnBridge` call post-upgrade and receives an authorization failure.

---

### Recommendation

1. Add an `AdminToPermissions` repeated field (e.g., `repeated AddressPermissions admin_to_permissions = 4`) to the `GenesisState` proto.
2. Add a keeper iterator over `KeyPrefixAdminToPermissions` and call it in `ExportGenesis`.
3. Restore entries in `InitGenesis` via `SetPermissions` for each exported entry.
4. Add a genesis round-trip integration test that grants permissions to N addresses, exports, imports, and asserts `GetPermissions` returns the original values.

---

### Proof of Concept

```
1. Grant CanChangeTokenMapping to address A via MsgUpdatePermissions (admin tx).
2. Verify: GetPermissions(A) == 1.
3. Export genesis: ExportGenesis(ctx, keeper) → GenesisState.
4. Inspect GenesisState: no AdminToPermissions field present.
5. Import into fresh chain: InitGenesis(ctx, keeper, genesisState).
6. Assert: GetPermissions(A) == 0.  ← permissions silently lost
7. A attempts MsgUpdateTokenMapping → rejected with "unauthorized".
```

### Citations

**File:** x/cronos/keeper/permissions.go (L19-23)
```go
func (k Keeper) SetPermissions(ctx sdk.Context, address sdk.AccAddress, permissions uint64) {
	store := ctx.KVStore(k.storeKey)
	permissionsBytes := sdk.Uint64ToBigEndian(permissions)
	store.Set(types.AdminToPermissionsKey(address), permissionsBytes)
}
```

**File:** x/cronos/keeper/permissions.go (L32-48)
```go
func (k Keeper) HasPermission(ctx sdk.Context, accounts []sdk.AccAddress, permissionsToCheck uint64) bool {
	// case when no permission is needed
	if permissionsToCheck == 0 {
		return true
	}
	admin := k.GetParams(ctx).CronosAdmin
	for _, account := range accounts {
		if admin == account.String() {
			return true
		}
		permission := k.GetPermissions(ctx, account)
		if permission&permissionsToCheck == permissionsToCheck {
			return true
		}
	}

	return false
```

**File:** x/cronos/types/genesis.pb.go (L27-32)
```go
type GenesisState struct {
	// params defines all the paramaters of the module.
	Params            Params         `protobuf:"bytes,1,opt,name=params,proto3" json:"params"`
	ExternalContracts []TokenMapping `protobuf:"bytes,2,rep,name=external_contracts,json=externalContracts,proto3" json:"external_contracts"`
	AutoContracts     []TokenMapping `protobuf:"bytes,3,rep,name=auto_contracts,json=autoContracts,proto3" json:"auto_contracts"`
}
```

**File:** x/cronos/genesis.go (L16-55)
```go
func InitGenesis(ctx sdk.Context, k keeper.Keeper, genState types.GenesisState) {
	if err := k.SetParams(ctx, genState.Params); err != nil {
		panic(fmt.Sprintf("Invalid cronos module params: %v\n", genState.Params))
	}

	for _, m := range genState.ExternalContracts {
		// Only allow IBC, gravity, or cronos denoms at genesis.
		if !types.IsValidIBCDenom(m.Denom) && !types.IsValidGravityDenom(m.Denom) && !types.IsValidCronosDenom(m.Denom) {
			panic(fmt.Sprintf("Invalid denom to map to contract: %s", m.Denom))
		}
		if !common.IsHexAddress(m.Contract) {
			panic(fmt.Sprintf("Invalid contract address: %s", m.Contract))
		}
		if err := k.SetExternalContractForDenom(ctx, m.Denom, common.HexToAddress(m.Contract)); err != nil {
			panic(err)
		}
	}

	for _, m := range genState.AutoContracts {
		// Only allow IBC, gravity, or cronos denoms at genesis.
		if !types.IsValidIBCDenom(m.Denom) && !types.IsValidGravityDenom(m.Denom) && !types.IsValidCronosDenom(m.Denom) {
			panic(fmt.Sprintf("Invalid denom to map to contract: %s", m.Denom))
		}
		if !common.IsHexAddress(m.Contract) {
			panic(fmt.Sprintf("Invalid contract address: %s", m.Contract))
		}
		if err := k.SetAutoContractForDenom(ctx, m.Denom, common.HexToAddress(m.Contract)); err != nil {
			if errors.Is(err, types.ErrExternalMappingExists) || errors.Is(err, types.ErrDenomAlreadyMapped) {
				k.Logger(ctx).Info("skipping auto contract import, denom mapping already exists",
					"denom", m.Denom, "contract", m.Contract, "error", err)
				continue
			}
			panic(err)
		}
	}

	// this line is used by starport scaffolding # genesis/module/init

	// this line is used by starport scaffolding # ibc/genesis/init
}
```

**File:** x/cronos/genesis.go (L58-69)
```go
func ExportGenesis(ctx sdk.Context, k keeper.Keeper) *types.GenesisState {
	// this line is used by starport scaffolding # genesis/module/export

	// this line is used by starport scaffolding # ibc/genesis/export

	// Auto and external contracts are mutually exclusive for non-source denoms:
	// SetExternalContractForDenom retires any auto mapping for the same denom.
	return &types.GenesisState{
		Params:            k.GetParams(ctx),
		ExternalContracts: k.GetExternalContracts(ctx),
		AutoContracts:     k.GetAutoContracts(ctx),
	}
```

**File:** x/cronos/types/keys.go (L40-40)
```go
	KeyPrefixAdminToPermissions = []byte{prefixAdminToPermissions}
```
