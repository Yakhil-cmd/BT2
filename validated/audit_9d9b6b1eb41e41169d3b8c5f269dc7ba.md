### Title
No Timelock on Cadence Contract Updates Allows Malicious Contract Author to Instantly Drain User Funds - (File: fvm/environment/contract_updater.go)

### Summary
The Flow FVM's `SetContract` function in `contract_updater.go` explicitly skips all authorization checks for contract **updates** (as opposed to initial deployments), and no timelock or delay mechanism exists anywhere in the update path. A malicious Cadence contract author can deploy a legitimate-looking staking or DeFi contract, attract user funds, and then instantly push malicious code that drains those funds — with no window for users to react.

### Finding Description
In `fvm/environment/contract_updater.go`, the `SetContract` function is the single gate for both initial contract deployments and contract updates. The code explicitly comments:

> "Initial contract deployments must be authorized by signing accounts. Contract updates are always allowed."

The authorization check (`isAuthorizedForDeployment`) is guarded by `!exists`, meaning it is **only enforced for new deployments**. When a contract already exists at the given address, the entire authorization path is skipped and the update is queued unconditionally:

```go
if !exists && !updater.isAuthorizedForDeployment(signingAccounts) {
    return fmt.Errorf("deploying contract failed: ...")
}
// If exists == true, falls through with no check at all
updater.draftUpdates[location] = ContractUpdate{Location: location, Code: code}
``` [1](#0-0) 

The update is committed immediately at the end of the transaction via `Commit()`, with no delay, staging period, or timelock: [2](#0-1) 

The public entry point `UpdateAccountContractCode` passes directly to `SetContract` with no additional guard: [3](#0-2) 

### Impact Explanation
A malicious Cadence contract author can:
1. Deploy a legitimate-looking staking contract with attractive APR (initial deployment requires authorization from the service account allowlist, but once granted, the contract is live).
2. Attract users to deposit FLOW tokens into the contract.
3. In a single transaction, call `account.contracts.update(name: "StakingContract", code: maliciousCode)` — this flows through `UpdateAccountContractCode` → `SetContract`, where `exists == true` causes the authorization check to be skipped entirely.
4. The malicious code takes effect immediately in the next transaction, enabling the attacker to call a new drain function and steal all deposited user funds.

There is no timelock, no staging delay, and no user-facing warning period anywhere in the FVM update path. The impact is direct, unauthorized movement of user on-chain assets. [4](#0-3) 

### Likelihood Explanation
The likelihood is **high**. The attacker-controlled entry path is a standard Cadence transaction signed by the contract account owner — no privileged keys, no node compromise, no social engineering beyond the initial contract deployment. The pattern (deploy attractive contract → attract funds → upgrade to malicious code) is a well-known rug-pull vector. The Flow FVM explicitly documents that "Contract updates are always allowed," confirming this is a reachable, unconditional code path. [5](#0-4) 

### Recommendation
Introduce a mandatory timelock for contract updates at the FVM level. When `exists == true` and the update is not from the service account, the update should be staged (not immediately committed) and only applied after a configurable delay (e.g., N blocks or epochs). This gives users time to withdraw funds before a malicious update takes effect. Alternatively, the `Commit()` path should enforce a minimum block-height delay between staging and applying an update for non-system contracts. [2](#0-1) 

### Proof of Concept

**Step 1 — Deploy a legitimate staking contract (requires service account authorization):**
```cadence
transaction {
    prepare(signer: auth(UpdateContract) &Account) {
        signer.contracts.add(name: "StakingVault", code: legitimateCode.utf8)
    }
}
```

**Step 2 — Users deposit FLOW tokens into `StakingVault`.**

**Step 3 — Attacker instantly pushes malicious update (no timelock, no delay):**
```cadence
transaction {
    prepare(signer: auth(UpdateContract) &Account) {
        // SetContract is called with exists==true → authorization check skipped
        signer.contracts.update(name: "StakingVault", code: maliciousCode.utf8)
    }
}
```

**Step 4 — Attacker calls the new drain function in the same or next block:**
```cadence
transaction {
    execute {
        StakingVault.drainAllFunds(to: attackerAddress)
    }
}
```

The FVM's `SetContract` at line 387 only checks `!exists && !updater.isAuthorizedForDeployment(...)`. Since `exists == true` for the update in Step 3, the check is never evaluated, the update is queued unconditionally, and `Commit()` writes it to state with no delay. [6](#0-5)

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
