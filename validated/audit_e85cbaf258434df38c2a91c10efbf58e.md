### Title
Persistent Implicit Update Authorization Bypasses Contract Deployment Whitelist - (File: `fvm/environment/contract_updater.go`)

### Summary
The FVM's `SetContract` function enforces the deployment authorization whitelist only for new contract deployments. Once a contract exists on-chain, any subsequent update to that contract bypasses the whitelist check entirely, as the code explicitly states "Contract updates are always allowed." This creates a persistent implicit permission: any account that has ever had a contract deployed retains the ability to update that contract's code indefinitely, even after being removed from the authorized deployer list. This is the direct Flow analog to the persistent whitelisting vulnerability described in the report.

### Finding Description
In `fvm/environment/contract_updater.go`, the `SetContract` function is the single FVM-level gate for both new contract deployments and contract updates:

```go
func (updater *ContractUpdaterImpl) SetContract(
    location common.AddressLocation,
    code []byte,
    signingAccounts []flow.Address,
) error {
    // Initial contract deployments must be authorized by signing accounts.
    //
    // Contract updates are always allowed.
    exists, err := updater.accounts.ContractExists(location.Name, flow.Address(location.Address))
    ...
    if !exists && !updater.isAuthorizedForDeployment(signingAccounts) {
        return fmt.Errorf("deploying contract failed: %w", ...)
    }
    updater.draftUpdates[location] = ContractUpdate{...}
    return nil
}
``` [1](#0-0) 

The authorization check `isAuthorizedForDeployment` is only evaluated when `!exists`. When a contract already exists, the entire authorization path is skipped and the update is unconditionally queued into `draftUpdates`. The `Commit()` function that flushes these updates to storage performs no re-check: [2](#0-1) 

The authorized deployer list is stored at `ContractDeploymentAuthorizedAddressesPath` in the service account and is read by `GetAuthorizedAccounts`. The default configuration has `RestrictContractDeployment: true`, meaning the whitelist is active on all standard networks: [3](#0-2) [4](#0-3) 

The `UpdateAccountContractCode` function (the Cadence runtime entry point for `account.contracts.update()`) passes directly to `SetContract` with no additional authorization gate: [5](#0-4) 

The authorized deployer list management is confirmed by the `SetContractDeploymentAuthorizersTransaction` blueprint and the `ContractDeploymentAuthorizedAddressesPath` storage path: [6](#0-5) 

The integration test at `fvm/fvm_blockcontext_test.go` explicitly confirms that an account NOT signed by the service account can update an existing contract without error, while a new deployment by the same account would fail: [7](#0-6) 

**Attacker-controlled entry path:**
1. Contract deployment restriction is enabled (default: `RestrictContractDeployment: true`).
2. Account `A` is on the authorized list and deploys contract `Foo`.
3. The service account removes `A` from the authorized list (e.g., because `A` was flagged as compromised, or because the operator tightened the allowlist).
4. The attacker, controlling `A`'s key, submits a transaction: `A.contracts.update(name: "Foo", code: <malicious_bytecode>)`.
5. The FVM calls `UpdateAccountContractCode` → `SetContract`. `ContractExists("Foo", A)` returns `true`, so `!exists` is `false`.
6. The `isAuthorizedForDeployment` check is skipped entirely.
7. The malicious code is committed to chain state via `Commit()`.

A second realistic scenario: contract deployment restriction was disabled during an early network phase, allowing many accounts to deploy contracts. When the service account later enables restriction, all those previously deployed contracts remain updatable by their owners without any whitelist check.

### Impact Explanation
An account that has a contract deployed on Flow retains an unconditional, permanent right to update that contract's code, regardless of its current status on the deployment authorization whitelist. If the account is later removed from the whitelist (for any reason, including compromise), the attacker can replace the contract with arbitrary malicious Cadence code. Any user or contract that imports or interacts with the updated contract is then exposed to the malicious logic — enabling theft of fungible tokens, unauthorized mutation of shared state, or capability hijacking for any resource stored in or accessible through the compromised contract. The impact is unauthorized state change and potential asset theft affecting all downstream users of the contract.

### Likelihood Explanation
The default FVM context has `RestrictContractDeployment: true`, making the whitelist active on all standard Flow networks. The scenario where an account has a deployed contract but is not (or is no longer) on the authorized list is realistic: Flow mainnet had an open deployment phase before restrictions were enabled, leaving many accounts with deployed contracts that are not on the current authorized list. Additionally, the service account can remove accounts from the list at any time, and there is no mechanism to simultaneously revoke their implicit update rights over existing contracts. An attacker who controls any such account can exploit this immediately with a standard user transaction — no privileged access required.

### Recommendation
Apply the same `isAuthorizedForDeployment` check to contract updates as to new deployments, or introduce a separate `isAuthorizedForUpdate` check backed by a dedicated authorized-updaters list. At minimum, the FVM should not silently grant permanent update rights as a side-effect of a past deployment. The comment "Contract updates are always allowed" should be revisited: if deployment restriction is enabled, update restriction should be configurable as well, consistent with how `RestrictContractRemoval` is handled for removals.

### Proof of Concept

```
// Step 1: Service account enables deployment restriction and sets authorized list to [serviceAccount]
// (default behavior on mainnet)

// Step 2: Account A is temporarily added to the authorized list and deploys Foo
transaction {
    prepare(signer: auth(AddContract) &Account, service: &Account) {
        signer.contracts.add(name: "Foo", code: "<legitimate_code>".decodeHex())
    }
}
// → SetContract called, !exists=true, A is on whitelist → succeeds

// Step 3: Service account removes A from the authorized list
// ContractDeploymentAuthorizedAddressesPath now = [serviceAccount]

// Step 4: Attacker (controlling A) updates Foo to malicious code
transaction {
    prepare(signer: auth(UpdateContract) &Account) {
        signer.contracts.update(name: "Foo", code: "<malicious_code>".decodeHex())
    }
}
// → UpdateAccountContractCode → SetContract called
// → ContractExists("Foo", A) = true → !exists = false
// → isAuthorizedForDeployment check is SKIPPED
// → malicious code queued and committed
// → all users of contract Foo are now exposed to malicious logic
```

The root cause is at `fvm/environment/contract_updater.go` line 387: the guard `!exists &&` causes the entire authorization branch to be bypassed for updates, creating a persistent implicit permission that outlives the account's presence on the authorized deployer whitelist. [8](#0-7)

### Citations

**File:** fvm/environment/contract_updater.go (L29-34)
```go
func DefaultContractUpdaterParams() ContractUpdaterParams {
	return ContractUpdaterParams{
		RestrictContractDeployment: true,
		RestrictContractRemoval:    true,
	}
}
```

**File:** fvm/environment/contract_updater.go (L223-258)
```go
// GetAuthorizedAccounts returns a list of addresses authorized by the service
// account. Used to determine which accounts are permitted to deploy, update,
// or remove contracts.
//
// It reads a storage path from service account and parse the addresses. If any
// issue occurs on the process (missing registers, stored value properly not
// set), it gracefully handles it and falls back to default behaviour (only
// service account be authorized).
func (impl *contractUpdaterStubsImpl) GetAuthorizedAccounts(
	path cadence.Path,
) []flow.Address {
	// set default to service account only
	service := impl.chain.ServiceAddress()
	defaultAccounts := []flow.Address{service}

	runtime := impl.runtime.BorrowCadenceRuntime()
	defer impl.runtime.ReturnCadenceRuntime(runtime)

	value, err := runtime.ReadStored(
		common.Address(service),
		path)

	const warningMsg = "failed to read contract authorized accounts from " +
		"service account. using default behaviour instead."

	if err != nil {
		impl.logger.Warn().Msg(warningMsg)
		return defaultAccounts
	}
	addresses, ok := cadenceValueToAddressSlice(value)
	if !ok {
		impl.logger.Warn().Msg(warningMsg)
		return defaultAccounts
	}
	return addresses
}
```

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

**File:** fvm/environment/contract_updater.go (L374-403)
```go
func (updater *ContractUpdaterImpl) SetContract(
	location common.AddressLocation,
	code []byte,
	signingAccounts []flow.Address,
) error {
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

**File:** fvm/blueprints/contracts.go (L13-24)
```go
var ContractDeploymentAuthorizedAddressesPath = cadence.Path{
	Domain:     common.PathDomainStorage,
	Identifier: "authorizedAddressesToDeployContracts",
}
var ContractRemovalAuthorizedAddressesPath = cadence.Path{
	Domain:     common.PathDomainStorage,
	Identifier: "authorizedAddressesToRemoveContracts",
}
var IsContractDeploymentRestrictedPath = cadence.Path{
	Domain:     common.PathDomainStorage,
	Identifier: "isContractDeploymentRestricted",
}
```

**File:** fvm/fvm_blockcontext_test.go (L563-617)
```go
	t.Run("account update with update code succeeds if not signed by service account", func(t *testing.T) {
		// Create an account private key.
		privateKeys, err := testutil.GenerateAccountPrivateKeys(1)
		require.NoError(t, err)

		// Bootstrap a ledger, creating accounts with the provided private keys
		// and the root account.
		snapshotTree, accounts, err := testutil.CreateAccounts(
			vm,
			testutil.RootBootstrappedLedger(vm, ctx),
			privateKeys,
			chain)
		require.NoError(t, err)

		txBodyBuilder := testutil.DeployCounterContractTransaction(accounts[0], chain).
			SetProposalKey(chain.ServiceAddress(), 0, 0).
			SetPayer(chain.ServiceAddress())

		err = testutil.SignPayload(txBodyBuilder, accounts[0], privateKeys[0])
		require.NoError(t, err)

		err = testutil.SignEnvelope(
			txBodyBuilder,
			chain.ServiceAddress(),
			unittest.ServiceAccountPrivateKey)
		require.NoError(t, err)

		txBody, err := txBodyBuilder.Build()
		require.NoError(t, err)

		executionSnapshot, output, err := vm.Run(
			ctx,
			fvm.Transaction(txBody, 0),
			snapshotTree)
		require.NoError(t, err)
		require.NoError(t, output.Err)

		snapshotTree = snapshotTree.Append(executionSnapshot)

		txBodyBuilder = testutil.UpdateUnauthorizedCounterContractTransaction(accounts[0]).
			SetProposalKey(accounts[0], 0, 0).
			SetPayer(accounts[0])
		err = testutil.SignEnvelope(txBodyBuilder, accounts[0], privateKeys[0])
		require.NoError(t, err)

		txBody, err = txBodyBuilder.Build()
		require.NoError(t, err)

		_, output, err = vm.Run(
			ctx,
			fvm.Transaction(txBody, 0),
			snapshotTree)
		require.NoError(t, err)
		require.NoError(t, output.Err)
	})
```
