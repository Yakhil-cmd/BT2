Now I have enough to write the finding. The core issue is in `fvm/environment/contract_updater.go`: `SetContract` skips all authorization for updates to existing contracts, but `Commit()` determines deletion by `len(v.Code) == 0` — meaning `UpdateAccountContractCode` with empty code silently deletes a contract, bypassing the `isAuthorizedForRemoval` check that `RemoveAccountContractCode` enforces.

---

### Title
Contract Removal Authorization Bypassed via `UpdateAccountContractCode` with Empty Code - (File: `fvm/environment/contract_updater.go`)

### Summary

`RemoveAccountContractCode` enforces `isAuthorizedForRemoval` before staging a contract deletion. `UpdateAccountContractCode` calls `SetContract`, which explicitly skips all authorization for updates to existing contracts. Because `Commit()` determines whether to delete a contract solely by `len(v.Code) == 0`, an account owner can delete their own contract by calling `contracts.update` with empty code, bypassing the removal restriction entirely. This is the direct analog of the reported pattern: the "delete" operation (`RemoveAccountContractCode`) has a consent/authorization gate, but the "update" operation (`UpdateAccountContractCode`) does not, even when the net effect is identical contract deletion.

### Finding Description

`SetContract` contains an explicit comment and branch: "Initial contract deployments must be authorized by signing accounts. Contract updates are always allowed." [1](#0-0) 

When `exists == true`, no authorization check of any kind is performed — neither `isAuthorizedForDeployment` nor `isAuthorizedForRemoval`. The draft update is stored with whatever `code` was passed: [2](#0-1) 

At commit time, the deletion decision is made purely on code length: [3](#0-2) 

The proper removal path, `RemoveContract`, enforces `isAuthorizedForRemoval`: [4](#0-3) 

`isAuthorizedForRemoval` gates on `RestrictedRemovalEnabled()`, which defaults to `true` (`RestrictContractRemoval: true`), and falls back to service-account-only when the authorized list is unreadable: [5](#0-4) [6](#0-5) 

The `UpdateAccountContractCode` entry point accepts arbitrary `[]byte` with no non-empty validation: [7](#0-6) 

**Exploit path:**
1. Attacker owns account `A` with contract `Foo` deployed.
2. Attacker is not in the `ContractRemovalAuthorizedAddressesPath` list (i.e., not the service account).
3. Attacker submits a transaction:
   ```cadence
   transaction {
     prepare(signer: auth(UpdateContract) &Account) {
       signer.contracts.update(name: "Foo", code: "".decodeHex())
     }
   }
   ```
4. Cadence runtime calls `UpdateAccountContractCode(location, []byte{})`.
5. `SetContract` sees `exists == true` → skips all authorization → stages `ContractUpdate{Code: []byte{}}`.
6. `Commit()` evaluates `len([]byte{}) == 0` → `shouldDelete = true` → calls `accounts.DeleteContract`.
7. Contract `Foo` is deleted. No `isAuthorizedForRemoval` check was ever performed.

### Impact Explanation

When `RestrictedRemovalEnabled()` is true (the default), the protocol's intent is that only accounts explicitly listed in `ContractRemovalAuthorizedAddressesPath` (defaulting to the service account) may delete contracts. This bypass allows any account owner to unilaterally delete their own deployed contract, circumventing that governance control. The impact is unauthorized, irreversible on-chain state mutation: contract code is permanently destroyed without the required authorization. Any dependent contracts, resources, or capabilities that relied on the deleted contract's existence are broken.

### Likelihood Explanation

The attacker precondition is minimal: own any Flow account that has a contract deployed. No privileged keys, no admin access, no staked node role is required. The transaction is a standard user transaction signed only by the account owner. The bypass is reachable on any network where `RestrictContractRemoval` is `true` (the default) and the attacker's account is not in the authorized removal list.

### Recommendation

`UpdateAccountContractCode` (and therefore `SetContract`) must reject empty code, or `SetContract` must apply `isAuthorizedForRemoval` when the incoming code is empty and the contract already exists. The simplest fix is to add a guard at the top of `UpdateAccountContractCode`:

```go
if len(code) == 0 {
    return errors.NewInvalidArgumentErrorf(
        "update account contract code failed: code must not be empty; use RemoveAccountContractCode to remove a contract")
}
```

Alternatively, `SetContract` should detect the empty-code-on-existing-contract case and route it through the same `isAuthorizedForRemoval` check that `RemoveContract` uses.

### Proof of Concept

```cadence
// Attacker transaction — no service account signature required
transaction {
  prepare(signer: auth(UpdateContract) &Account) {
    // "Foo" is an existing contract on signer's account.
    // Passing empty code triggers deletion in Commit()
    // without invoking isAuthorizedForRemoval.
    signer.contracts.update(name: "Foo", code: "".decodeHex())
  }
}
```

**Trace through FVM:**
- `UpdateAccountContractCode(location{"Foo", addr}, []byte{})` [8](#0-7) 
- `SetContract(location, []byte{}, signingAccounts)`: `exists=true` → branch `!exists && ...` is `false` → no auth check → `draftUpdates[location] = {Code: []byte{}}` [9](#0-8) 
- `Commit()`: `shouldDelete = len([]byte{}) == 0` → `true` → `accounts.DeleteContract(...)` executes [3](#0-2) 
- `isAuthorizedForRemoval` is never called; `RemoveContract` is never called.

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
