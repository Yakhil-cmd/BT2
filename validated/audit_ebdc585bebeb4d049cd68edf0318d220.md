### Title
Unprotected Contract Upgrade Bypasses Deployment Authorization Restriction — (`File: fvm/environment/contract_updater.go`)

---

### Summary

In `fvm/environment/contract_updater.go`, the `SetContract` function enforces the authorized-deployers check only for **new** contract deployments. When a contract already exists on an account, the update path is unconditionally allowed — no authorization check is performed. This is the direct Flow analog of the reported `_authorizeUpgrade()` missing access control: any account that already holds a deployed contract can upgrade it to arbitrary code, even after being removed from the authorized deployers list.

---

### Finding Description

`SetContract` is the single FVM entry point for both deploying and upgrading Cadence contracts. It is called by `UpdateAccountContractCode`, which is the Cadence runtime callback invoked whenever a transaction executes `signer.contracts.update(...)`.

The authorization gate reads:

```go
// Initial contract deployments must be authorized by signing accounts.
//
// Contract updates are always allowed.
exists, err := updater.accounts.ContractExists(location.Name, flow.Address(location.Address))
...
if !exists && !updater.isAuthorizedForDeployment(signingAccounts) {
    return fmt.Errorf("deploying contract failed: %w", ...)
}
// No authorization check when exists == true
updater.draftUpdates[location] = ContractUpdate{Location: location, Code: code}
``` [1](#0-0) 

The `isAuthorizedForDeployment` function consults the on-chain `ContractDeploymentAuthorizedAddressesPath` list (stored in the service account) when `RestrictedDeploymentEnabled()` returns `true`. [2](#0-1) 

The restriction flag is read from chain state via `getIsContractDeploymentRestricted`, which reads `blueprints.IsContractDeploymentRestrictedPath` from the service account. [3](#0-2) 

When `exists == true`, the entire authorization branch is skipped. The update is queued unconditionally and committed by `Commit()`. [4](#0-3) 

---

### Impact Explanation

When contract deployment is restricted (the production mainnet configuration), only accounts in the authorized list may deploy new contracts. However, any account that already holds a deployed contract — regardless of whether it is still in the authorized list — can call `signer.contracts.update(name: "X", code: <arbitrary>)` in a transaction and replace the contract's bytecode with arbitrary Cadence code. This allows:

- Injection of malicious logic into a previously-trusted contract (e.g., draining resources, minting tokens, bypassing access controls).
- Circumvention of the governance-controlled authorized-deployers list, which is the protocol's primary mechanism for controlling what code runs on-chain.

The impact matches the reported target scope: unauthorized mutation of on-chain contract code by an unprivileged transaction sender.

---

### Likelihood Explanation

**Medium.** The precondition is that the attacker controls an account that already has a contract deployed on it. On mainnet, contract deployment is restricted, so accounts with deployed contracts are a finite, known set. If any such account is later considered untrusted (e.g., a previously authorized third-party developer whose authorization was revoked), they retain the ability to upgrade their contract indefinitely. The attacker-controlled entry path is a standard signed Flow transaction — no special node access or key compromise is required.

---

### Recommendation

Apply the same `isAuthorizedForDeployment` check to contract updates as is applied to new deployments. The condition should be:

```go
if !updater.isAuthorizedForDeployment(signingAccounts) {
    return fmt.Errorf("updating contract failed: %w",
        errors.NewOperationAuthorizationErrorf(
            "SetContract",
            "updating contracts requires authorization from specific accounts"))
}
```

This mirrors the pattern already used for `RemoveContract`, which always checks `isAuthorizedForRemoval` regardless of whether the contract exists. [5](#0-4) 

---

### Proof of Concept

The following Cadence transaction, signed only by `accountA` (which holds an existing contract but has been removed from the authorized deployers list), succeeds under the current implementation:

```cadence
// Transaction signed by accountA (not in authorized deployers list)
transaction {
    prepare(signer: auth(UpdateContract) &Account) {
        // accountA already has "MyContract" deployed
        // This update bypasses isAuthorizedForDeployment because exists == true
        signer.contracts.update(
            name: "MyContract",
            code: "<malicious replacement code>".decodeHex()
        )
    }
}
```

In Go test terms, using the existing fixture `UpdateContractUnathorizedDeploymentTransaction`: [6](#0-5) 

This fixture already demonstrates the pattern — it uses `auth(UpdateContract)` without requiring service account co-signing, confirming the update path is reachable by any account owner with an existing contract, independent of the authorized deployers list.

### Citations

**File:** fvm/environment/contract_updater.go (L171-181)
```go
func (impl *contractUpdaterStubsImpl) RestrictedDeploymentEnabled() bool {
	enabled, defined := impl.getIsContractDeploymentRestricted()
	if !defined {
		// If the contract deployment bool is not set by the state
		// fallback to the default value set by the configuration
		// after the contract deployment bool is set by the state on all
		// chains, this logic can be simplified
		return impl.RestrictContractDeployment
	}
	return enabled
}
```

**File:** fvm/environment/contract_updater.go (L379-402)
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

**File:** fvm/environment/contract_updater.go (L450-463)
```go
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
