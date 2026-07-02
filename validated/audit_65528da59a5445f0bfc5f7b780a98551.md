### Title
Unrestricted Contract Update Bypasses Deployment Authorization — (`fvm/environment/contract_updater.go`)

---

### Summary

`SetContract` in the FVM contract updater unconditionally skips the deployment authorization check when a contract already exists at the target address. The comment in the code explicitly documents this as intentional: *"Contract updates are always allowed."* This means that once any account has a contract deployed, it can replace that contract with arbitrary code at any time, regardless of whether the account is still in the authorized deployment list. This is a direct analog to the external report's missing post-initialization validation: the authorization restriction is enforced at deployment time but silently absent for the update path, leaving a permanent privilege that cannot be revoked.

---

### Finding Description

In `fvm/environment/contract_updater.go`, `SetContract` checks authorization only for initial deployments (`!exists`). When the contract already exists, the entire `isAuthorizedForDeployment` gate is skipped unconditionally:

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

`isAuthorizedForDeployment` consults the on-chain authorized-addresses list stored at `ContractDeploymentAuthorizedAddressesPath` in the service account, and returns `false` when `RestrictedDeploymentEnabled()` is true and the signer is not in that list: [2](#0-1) 

Because the `exists` branch never calls `isAuthorizedForDeployment`, an account that was previously authorized to deploy a contract but has since been removed from the authorized list retains the permanent ability to overwrite that contract with arbitrary code. The test suite explicitly validates and preserves this behavior: [3](#0-2) 

---

### Impact Explanation

An account that owns a deployed contract can replace its bytecode with arbitrary malicious Cadence code at any time, even after being removed from the deployment authorized list. Depending on what contract is targeted, this enables:

- **Token minting**: replacing a fungible token contract to add an unrestricted `mint` function callable by the attacker.
- **Fund drainage**: replacing a vault or escrow contract to redirect withdrawals.
- **Privilege escalation**: replacing any contract that other contracts import and trust, injecting malicious logic into dependent contracts at their next execution.

The impact matches the external report's target scope: unauthorized state changes and unauthorized movement of assets via a missing authorization check in a critical initialization/update path.

---

### Likelihood Explanation

The entry path requires only that the attacker:
1. Own a Flow account with at least one contract already deployed (achievable by any user during any period when deployment is unrestricted, or when they were previously authorized).
2. Submit a standard transaction calling `account.contracts.update()` with `UpdateContract` entitlement on their own account — a normal, unprivileged operation.

No admin keys, staked nodes, or privileged access are required. The `UpdateContract` entitlement is automatically held by any account over its own storage. The missing check is reachable by any ordinary transaction sender.

---

### Recommendation

Apply `isAuthorizedForDeployment` to both the initial deployment and the update path when `RestrictedDeploymentEnabled()` is true. The guard should be:

```go
if !updater.isAuthorizedForDeployment(signingAccounts) {
    return fmt.Errorf("deploying/updating contract failed: %w",
        errors.NewOperationAuthorizationErrorf(...))
}
```

This removes the `!exists` condition so that the authorization list is enforced for both new deployments and updates. If the intent is to allow account owners to always update their own contracts regardless of the global restriction, that policy should be explicitly documented and the authorized-list mechanism should be described as deployment-only, not update-gating.

---

### Proof of Concept

1. Bootstrap a chain with `RestrictedContractDeployment = true` and an authorized list containing only the service account and `accounts[0]`.
2. As `accounts[0]` (authorized), deploy a contract — succeeds.
3. Remove `accounts[0]` from the authorized list via `SetContractDeploymentAuthorizersTransaction`.
4. As `accounts[0]` (now unauthorized), submit a transaction:
   ```cadence
   transaction {
     prepare(signer: auth(UpdateContract) &Account) {
       signer.contracts.update(name: "Counter", code: "<malicious_code>".decodeHex())
     }
   }
   ```
5. The FVM calls `UpdateAccountContractCode` → `SetContract` with `exists = true`; the `isAuthorizedForDeployment` check is skipped entirely; the malicious contract is committed to state. [4](#0-3) [5](#0-4)

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
