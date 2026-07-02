### Title
Contract Removal Without Outstanding Resource Validation Permanently Locks User Assets - (File: `fvm/environment/contract_updater.go`)

### Summary
`ContractUpdaterImpl.RemoveContract` in `fvm/environment/contract_updater.go` removes a Cadence contract from an account without verifying whether resources of that contract's defined types are currently held by other accounts. A malicious contract author can remove their contract while users hold resources of that type, permanently locking those assets with no recovery path.

### Finding Description
The `RemoveContract` function performs only an authorization check before scheduling the contract for deletion. It does not validate whether any resources defined by the contract exist in other accounts.

```go
func (updater *ContractUpdaterImpl) RemoveContract(
    location common.AddressLocation,
    signingAccounts []flow.Address,
) (err error) {
    // check if authorized
    if !updater.isAuthorizedForRemoval(signingAccounts) {
        return fmt.Errorf("removing contract failed: %w", ...)
    }

    u := ContractUpdate{Location: location}
    updater.draftUpdates[location] = u  // schedules deletion, no resource check

    return nil
}
```

At commit time, `Commit()` calls `accounts.DeleteContract`, which simply removes the contract code from storage with no resource existence check:

```go
if shouldDelete {
    contractUpdates.Deletions = append(contractUpdates.Deletions, v.Location)
    err = updater.accounts.DeleteContract(v.Location.Name, flow.Address(v.Location.Address))
```

`StatefulAccounts.DeleteContract` then removes the contract name from the account's contract name list and sets the contract code to `nil`, with no scan for outstanding resource instances.

### Impact Explanation
In Cadence, resources are linear types — they cannot be copied or implicitly destroyed. If the contract defining a resource type is removed, any resource instances of that type held in other accounts become permanently inaccessible: they cannot be moved, destroyed, or interacted with through the contract's functions (since the type definition no longer exists). The holders permanently lose access to those on-chain assets with no recovery mechanism.

### Likelihood Explanation
A malicious contract author can:
1. Deploy a contract defining an attractive resource type (e.g., a token vault, NFT, or staking receipt).
2. Attract users to store resources of that type in their accounts.
3. Call `account.contracts.remove(name: "...")` in a transaction signed by the contract-owning account.
4. The removal succeeds immediately with no check on outstanding resource holders.

When `RestrictedRemovalEnabled()` returns `false` (the default when `RestrictContractRemoval` is `false` in `ContractUpdaterParams`), any account owner can remove their own contracts unconditionally. Even when removal restriction is enabled, the authorized accounts can still perform this action.

### Recommendation
Before committing a contract deletion, validate that no resources of the contract's defined types are held in any account. If a full scan is infeasible, at minimum:
- Maintain a reference count of resource instances per contract type, incremented on resource creation and decremented on destruction.
- Reject contract removal if the reference count is non-zero.
- Alternatively, require a multi-step deprecation process: first mark the contract as deprecated (preventing new resource creation), then allow removal only after all existing resources have been destroyed.

### Proof of Concept
1. Deploy a contract `MyToken` that defines `resource Vault { ... }` from account `0x01`.
2. User `0x02` calls a function on `MyToken` to create and store a `@MyToken.Vault` in their account storage.
3. Account `0x01` submits a transaction:
   ```cadence
   transaction {
       prepare(signer: auth(RemoveContract) &Account) {
           signer.contracts.remove(name: "MyToken")
       }
   }
   ```
4. The transaction succeeds. `RemoveContract` checks only authorization, not resource holders.
5. `0x02`'s `@MyToken.Vault` is now permanently inaccessible — the type no longer exists, so no Cadence code can reference, move, or destroy it. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4)

### Citations

**File:** fvm/environment/contract_updater.go (L20-34)
```go
type ContractUpdaterParams struct {
	// Depricated: RestrictedDeploymentEnabled is deprecated use
	// SetIsContractDeploymentRestrictedTransaction instead.
	// Can be removed after all networks are migrated to
	// SetIsContractDeploymentRestrictedTransaction
	RestrictContractDeployment bool
	RestrictContractRemoval    bool
}

func DefaultContractUpdaterParams() ContractUpdaterParams {
	return ContractUpdaterParams{
		RestrictContractDeployment: true,
		RestrictContractRemoval:    true,
	}
}
```

**File:** fvm/environment/contract_updater.go (L405-422)
```go
func (updater *ContractUpdaterImpl) RemoveContract(
	location common.AddressLocation,
	signingAccounts []flow.Address,
) (err error) {
	// check if authorized
	if !updater.isAuthorizedForRemoval(signingAccounts) {
		return fmt.Errorf("removing contract failed: %w",
			errors.NewOperationAuthorizationErrorf(
				"RemoveContract",
				"removing contracts requires authorization from specific "+
					"accounts"))
	}

	u := ContractUpdate{Location: location}
	updater.draftUpdates[location] = u

	return nil
}
```

**File:** fvm/environment/contract_updater.go (L441-449)
```go
		shouldDelete := len(v.Code) == 0

		if shouldDelete {
			// this is a removal
			contractUpdates.Deletions = append(contractUpdates.Deletions, v.Location)
			err = updater.accounts.DeleteContract(v.Location.Name, flow.Address(v.Location.Address))
			if err != nil {
				return ContractUpdates{}, err
			}
```

**File:** fvm/environment/contract_updater.go (L507-516)
```go
func (updater *ContractUpdaterImpl) isAuthorizedForRemoval(
	signingAccounts []flow.Address,
) bool {
	if updater.RestrictedRemovalEnabled() {
		return updater.isAuthorized(
			signingAccounts,
			blueprints.ContractRemovalAuthorizedAddressesPath)
	}
	return true
}
```

**File:** fvm/environment/accounts.go (L962-979)
```go
func (a *StatefulAccounts) DeleteContract(
	contractName string,
	address flow.Address,
) error {
	contractNames, err := a.getContractNames(address)
	if err != nil {
		return err
	}
	if !contractNames.Has(contractName) {
		return nil
	}
	err = a.setContract(contractName, address, nil)
	if err != nil {
		return err
	}
	contractNames.remove(contractName)
	return a.setContractNames(contractNames, address)
}
```
