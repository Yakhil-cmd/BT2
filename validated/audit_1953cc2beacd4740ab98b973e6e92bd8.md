### Title
Missing Authorization Check on Contract Updates Allows Unauthorized Code Modification - (File: `fvm/environment/contract_updater.go`)

### Summary

`SetContract()` in `fvm/environment/contract_updater.go` explicitly skips the `isAuthorizedForDeployment()` check when a contract already exists. The comment reads: *"Contract updates are always allowed."* This means any account that owns an existing contract can update it without being in the `ContractDeploymentAuthorizedAddressesPath` authorized list, even when restricted deployment mode is enabled. This is the direct Flow analog of the Earning.sol `update()` missing `onlyAdmin` — a privileged state-mutation function that bypasses the access-control list.

---

### Finding Description

`SetContract()` is the single FVM function that handles both new contract deployments and updates to existing contracts. The authorization check is gated only on the `!exists` branch:

```go
// fvm/environment/contract_updater.go L379-395
// Initial contract deployments must be authorized by signing accounts.
//
// Contract updates are always allowed.
exists, err := updater.accounts.ContractExists(location.Name, flow.Address(location.Address))
...
if !exists && !updater.isAuthorizedForDeployment(signingAccounts) {
    return fmt.Errorf("deploying contract failed: ...")
}
// No authorization check when exists == true
updater.draftUpdates[location] = ContractUpdate{...}
``` [1](#0-0) 

The `ContractDeploymentAuthorizedAddressesPath` list is documented as controlling accounts permitted to **deploy or update** contracts:

```go
// SetContractDeploymentAuthorizersTransaction returns a transaction for
// updating list of authorized accounts allowed to deploy/update contracts
``` [2](#0-1) 

`isAuthorizedForDeployment()` consults this list only when `RestrictedDeploymentEnabled()` is true (the default):

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
``` [3](#0-2) 

The default `ContractUpdaterParams` enables restriction:

```go
func DefaultContractUpdaterParams() ContractUpdaterParams {
    return ContractUpdaterParams{
        RestrictContractDeployment: true,
        RestrictContractRemoval:    true,
    }
}
``` [4](#0-3) 

---

### Impact Explanation

When restricted deployment mode is active, the governance model intends that only accounts in the authorized list can modify contract code. However, any account that already has a deployed contract — regardless of whether it is in the authorized list — can freely update that contract's bytecode. This allows:

1. An account removed from the authorized list (e.g., after a governance decision) to continue modifying its deployed contracts.
2. An account that was never authorized but obtained a contract through other means (e.g., account transfer) to inject arbitrary new logic.
3. Bypassing the entire contract-update governance model, which is the core trust invariant of the restricted deployment system.

The `RemoveContract()` path correctly enforces authorization on every call:

```go
func (updater *ContractUpdaterImpl) RemoveContract(...) (err error) {
    if !updater.isAuthorizedForRemoval(signingAccounts) {
        return fmt.Errorf("removing contract failed: ...")
    }
    ...
}
``` [5](#0-4) 

The asymmetry — removal is checked, update is not — confirms this is an unintentional omission, not a deliberate design choice.

---

### Likelihood Explanation

The attack requires only that the attacker controls an account with an existing deployed contract and can submit a transaction with `auth(UpdateContract) &Account`. No privileged keys, no admin access, no staked node role. The Cadence entitlement `UpdateContract` is held by the account owner, which is a normal user capability. The existing integration test at `fvm/fvm_blockcontext_test.go` lines 563–616 explicitly demonstrates and passes this exact scenario:

```go
t.Run("account update with update code succeeds if not signed by service account", func(t *testing.T) {
    // deploys with service account authorization
    // then updates WITHOUT service account authorization
    txBodyBuilder = testutil.UpdateUnauthorizedCounterContractTransaction(accounts[0])
    ...
    require.NoError(t, output.Err)  // succeeds
})
``` [6](#0-5) 

The transaction used (`UpdateContractUnathorizedDeploymentTransaction`) requires only `auth(UpdateContract)` from the account owner — no service account co-signature:

```go
func UpdateContractUnathorizedDeploymentTransaction(...) *flow.TransactionBodyBuilder {
    return flow.NewTransactionBodyBuilder().
        SetScript(fmt.Appendf(nil, `transaction {
              prepare(signer: auth(UpdateContract) &Account) {
                signer.contracts.update(name: "%s", code: "%s".decodeHex())
              }
            }`, contractName, encoded),
        ).
        AddAuthorizer(authorizer)
}
``` [7](#0-6) 

---

### Recommendation

Apply `isAuthorizedForDeployment()` unconditionally in `SetContract()`, regardless of whether the contract already exists:

```go
func (updater *ContractUpdaterImpl) SetContract(
    location common.AddressLocation,
    code []byte,
    signingAccounts []flow.Address,
) error {
    if !updater.isAuthorizedForDeployment(signingAccounts) {
        return fmt.Errorf(
            "updating/deploying contract failed: %w",
            errors.NewOperationAuthorizationErrorf(
                "SetContract",
                "deploying or updating contracts requires authorization from specific accounts"))
    }
    updater.draftUpdates[location] = ContractUpdate{
        Location: location,
        Code:     code,
    }
    return nil
}
```

This mirrors the existing pattern used by `RemoveContract()`, which always checks `isAuthorizedForRemoval()` regardless of contract state.

---

### Proof of Concept

**Preconditions:** Restricted deployment mode is enabled (default). Account `A` is not in the `ContractDeploymentAuthorizedAddressesPath` list. Account `A` has a previously deployed contract `Foo`.

**Attack transaction:**
```cadence
transaction {
    prepare(signer: auth(UpdateContract) &Account) {
        signer.contracts.update(
            name: "Foo",
            code: "<malicious_replacement_bytecode>".decodeHex()
        )
    }
}
```
Signed only by account `A` (no service account co-signature).

**Result:** `SetContract()` is called with `exists == true`. The `isAuthorizedForDeployment()` check is skipped. The malicious code is written to the contract at `A.Foo`. The transaction succeeds with no error, as confirmed by the existing test at `fvm/fvm_blockcontext_test.go:563`. [8](#0-7) [9](#0-8)

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

**File:** fvm/environment/contract_updater.go (L405-421)
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
```

**File:** fvm/environment/contract_updater.go (L496-530)
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

func (updater *ContractUpdaterImpl) isAuthorized(
	signingAccounts []flow.Address,
	path cadence.Path,
) bool {
	accts := updater.GetAuthorizedAccounts(path)
	for _, authorized := range accts {
		if slices.Contains(signingAccounts, authorized) {
			// a single authorized singer is enough
			return true
		}
	}
	return false
}
```

**File:** fvm/blueprints/contracts.go (L35-38)
```go
// SetContractDeploymentAuthorizersTransaction returns a transaction for updating list of authorized accounts allowed to deploy/update contracts
func SetContractDeploymentAuthorizersTransaction(serviceAccount flow.Address, authorized []flow.Address) (*flow.TransactionBodyBuilder, error) {
	return setContractAuthorizersTransaction(ContractDeploymentAuthorizedAddressesPath, serviceAccount, authorized)
}
```

**File:** fvm/fvm_blockcontext_test.go (L563-616)
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
```

**File:** engine/execution/testutil/fixtures.go (L67-78)
```go
func UpdateContractUnathorizedDeploymentTransaction(contractName string, contract string, authorizer flow.Address) *flow.TransactionBodyBuilder {
	encoded := hex.EncodeToString([]byte(contract))

	return flow.NewTransactionBodyBuilder().
		SetScript(fmt.Appendf(nil, `transaction {
              prepare(signer: auth(UpdateContract) &Account) {
                signer.contracts.update(name: "%s", code: "%s".decodeHex())
              }
            }`, contractName, encoded),
		).
		AddAuthorizer(authorizer)
}
```
