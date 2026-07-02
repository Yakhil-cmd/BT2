### Title
Unrestricted Contract Update Bypasses Deployment Authorization Check — (`File: fvm/environment/contract_updater.go`)

### Summary
`SetContract` in the FVM contract updater enforces role-based authorization only for **new** contract deployments. When a contract already exists at the target address, the authorization check is unconditionally skipped with the comment "Contract updates are always allowed." This creates an asymmetric RBAC policy: an account not on the service account's authorized deployment list can freely replace existing contract code with arbitrary new code, bypassing the deployment restriction entirely.

### Finding Description

In `fvm/environment/contract_updater.go`, `SetContract` checks whether the contract already exists before deciding whether to enforce authorization:

```go
// Initial contract deployments must be authorized by signing accounts.
//
// Contract updates are always allowed.
exists, err := updater.accounts.ContractExists(location.Name, flow.Address(location.Address))
...
if !exists && !updater.isAuthorizedForDeployment(signingAccounts) {
    return fmt.Errorf("deploying contract failed: ...")
}
``` [1](#0-0) 

When `exists == true`, the entire authorization path is skipped. The `isAuthorizedForDeployment` function, when restricted deployment is enabled, checks whether the signing accounts appear in the service account's authorized deployment list: [2](#0-1) 

This check is never reached for updates. By contrast, `RemoveContract` always enforces its own authorization check regardless of state: [3](#0-2) 

The Cadence runtime enforces `auth(UpdateContract) &Account` access to the target account before calling `UpdateAccountContractCode`, which calls `SetContract`: [4](#0-3) 

This means the only gate on updates is that the transaction signer must be an authorizer of the target account — not that they are on the service account's authorized deployment list.

**Attacker-controlled entry path:**
1. Restricted deployment is enabled on the network (service account controls who can deploy new contracts).
2. An attacker controls an account that already has an existing contract (deployed before restrictions were enabled, or deployed by the service account on their behalf).
3. The attacker submits a transaction:
   ```cadence
   transaction {
     prepare(signer: auth(UpdateContract) &Account) {
       signer.contracts.update(name: "MyContract", code: <malicious_code>)
     }
   }
   ```
4. The Cadence runtime grants `auth(UpdateContract) &Account` because the signer is the account owner.
5. `SetContract` is called, finds `exists == true`, skips `isAuthorizedForDeployment`, and queues the update.
6. `Commit` writes the new malicious code to the account's contract storage. [5](#0-4) 

### Impact Explanation

When restricted deployment mode is active, the intent is to control what contract code runs on the network. The update bypass allows any account owner with an existing contract to replace that contract's code with arbitrary new logic — introducing backdoors, draining funds from callers, or breaking protocol invariants — without being on the authorized deployment list. The impact is scoped to contracts the attacker already owns, but those contracts may be called by other users or protocols that trust them.

**Impact: 4** — Unauthorized code mutation of on-chain contracts, bypassing the network's deployment access control policy.

### Likelihood Explanation

Requires: (a) restricted deployment mode is enabled, and (b) the attacker already owns an account with an existing contract. Both conditions are realistic on a network that has enabled deployment restrictions after initial bootstrapping. The attacker needs no special privileges beyond owning their own account.

**Likelihood: 3**

### Recommendation

Apply the same `isAuthorizedForDeployment` check to contract updates, not only to initial deployments. If the intent is to allow account owners to freely update their own contracts regardless of the authorized list, the policy should be explicitly documented and the deployment restriction should be scoped only to accounts that are not the contract's owner address. At minimum, the asymmetry between deployment (restricted) and update (unrestricted) should be a deliberate, documented policy decision rather than an implicit bypass.

### Proof of Concept

```cadence
// Attacker owns account 0xABCD which has an existing contract "Vault"
// Restricted deployment is enabled; 0xABCD is NOT on the authorized list.

transaction {
  prepare(signer: auth(UpdateContract) &Account) {
    // Cadence grants auth(UpdateContract) because signer == account owner.
    // FVM SetContract: exists==true → skips isAuthorizedForDeployment → queues update.
    signer.contracts.update(
      name: "Vault",
      code: "<malicious replacement draining all deposited tokens>"
    )
  }
}
```

`SetContract` at line 387 evaluates `!exists` as `false` and short-circuits, never calling `isAuthorizedForDeployment`. The update is committed at `Commit()` line 459 with no authorization check having been performed. [6](#0-5)

### Citations

**File:** fvm/environment/contract_updater.go (L320-346)
```go
func (updater *ContractUpdaterImpl) UpdateAccountContractCode(
	location common.AddressLocation,
	code []byte,
) error {
	defer updater.tracer.StartChildSpan(
		trace.FVMEnvUpdateAccountContractCode).End()

	err := updater.meter.MeterComputation(
		common.ComputationUsage{
			Kind:      ComputationKindUpdateAccountContractCode,
			Intensity: 1,
		},
	)
	if err != nil {
		return fmt.Errorf("update account contract code failed: %w", err)
	}

	err = updater.SetContract(
		location,
		code,
		updater.signingAccounts)
	if err != nil {
		return fmt.Errorf("updating account contract code failed: %w", err)
	}

	return nil
}
```

**File:** fvm/environment/contract_updater.go (L379-403)
```go
	// Initial contract deployments must be authorized by signing accounts.
	//
	// Contract updates are always allowed.
	exists, err := updater.accounts.ContractExists(location.Name, flow.Address(location.Address))
	if err != nil {
		return err
	}

	if !exists && !updater.isAuthorizedForDeployment(signingAccounts) {
		return fmt.Errorf(
			"deploying contract failed: %w",
			errors.NewOperationAuthorizationErrorf(
				"SetContract",
				"deploying contracts requires authorization from specific "+
					"accounts"))

	}

	updater.draftUpdates[location] = ContractUpdate{
		Location: location,
		Code:     code,
	}

	return nil
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

**File:** fvm/environment/contract_updater.go (L424-471)
```go
func (updater *ContractUpdaterImpl) Commit() (ContractUpdates, error) {
	updateList := updater.updates()
	updater.Reset()

	contractUpdates := ContractUpdates{
		Updates:   make([]common.AddressLocation, 0, len(updateList)),
		Deploys:   make([]common.AddressLocation, 0, len(updateList)),
		Deletions: make([]common.AddressLocation, 0, len(updateList)),
	}

	var err error
	for _, v := range updateList {
		var currentlyExists bool
		currentlyExists, err = updater.accounts.ContractExists(v.Location.Name, flow.Address(v.Location.Address))
		if err != nil {
			return ContractUpdates{}, err
		}
		shouldDelete := len(v.Code) == 0

		if shouldDelete {
			// this is a removal
			contractUpdates.Deletions = append(contractUpdates.Deletions, v.Location)
			err = updater.accounts.DeleteContract(v.Location.Name, flow.Address(v.Location.Address))
			if err != nil {
				return ContractUpdates{}, err
			}
		} else {
			if !currentlyExists {
				// this is a deployment
				contractUpdates.Deploys = append(contractUpdates.Deploys, v.Location)
			} else {
				// this is an update
				contractUpdates.Updates = append(contractUpdates.Updates, v.Location)
			}

			err = updater.accounts.SetContract(
				v.Location.Name,
				flow.Address(v.Location.Address),
				v.Code,
			)
			if err != nil {
				return ContractUpdates{}, err
			}
		}
	}

	return contractUpdates, nil
}
```

**File:** fvm/environment/contract_updater.go (L496-505)
```go
func (updater *ContractUpdaterImpl) isAuthorizedForDeployment(
	signingAccounts []flow.Address,
) bool {
	if updater.RestrictedDeploymentEnabled() {
		return updater.isAuthorized(
			signingAccounts,
			blueprints.ContractDeploymentAuthorizedAddressesPath)
	}
	return true
}
```
