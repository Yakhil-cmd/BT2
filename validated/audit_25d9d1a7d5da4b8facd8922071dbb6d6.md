### Title
Authorized-Deployers Restriction Bypassed for Existing Contract Updates, Enabling Immediate Malicious Code Replacement of Fund-Holding Contracts - (File: fvm/environment/contract_updater.go)

### Summary
The FVM's `ContractUpdaterImpl.SetContract` function enforces the authorized-deployers list only for **new** contract deployments. Updates to already-deployed contracts are unconditionally permitted with no authorization check and no timelock. A malicious Cadence contract author who owns an account with a deployed contract can replace that contract's code immediately, bypassing any post-deployment revocation of their deployment privileges, and drain any funds or capabilities the contract controls.

### Finding Description
In `fvm/environment/contract_updater.go`, `SetContract` reads:

```go
// Initial contract deployments must be authorized by signing accounts.
//
// Contract updates are always allowed.
exists, err := updater.accounts.ContractExists(location.Name, flow.Address(location.Address))
...
if !exists && !updater.isAuthorizedForDeployment(signingAccounts) {
    return fmt.Errorf("deploying contract failed: ...")
}
// no else-branch: if exists == true, update proceeds unconditionally
updater.draftUpdates[location] = ContractUpdate{Location: location, Code: code}
```

The comment "Contract updates are always allowed" is the explicit design statement. `isAuthorizedForDeployment` is only called when `!exists`. When `exists == true`, the signing-account list is never checked against `ContractDeploymentAuthorizedAddressesPath`.

`isAuthorizedForDeployment` itself returns `true` unconditionally when `RestrictedDeploymentEnabled()` is `false`, and otherwise consults the on-chain authorized-address list:

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

`RestrictedDeploymentEnabled` reads the on-chain flag; the default `ContractUpdaterParams` sets `RestrictContractDeployment: true`, meaning restriction is the intended production posture. Yet even with restriction enabled, the update path is never gated.

The `UpdateAccountContractCode` entry point passes `updater.signingAccounts` directly into `SetContract`, so the signing accounts of the transaction are the only identity available — and they are ignored for updates:

```go
func (updater *ContractUpdaterImpl) UpdateAccountContractCode(
    location common.AddressLocation,
    code []byte,
) error {
    ...
    err = updater.SetContract(location, code, updater.signingAccounts)
    ...
}
```

The integration test at `fvm/fvm_blockcontext_test.go` line 563 explicitly confirms this is reachable: `"account update with update code succeeds if not signed by service account"` — a non-service-account updates an existing contract and the transaction succeeds.

### Impact Explanation
Any account that owns a deployed contract can replace its bytecode with arbitrary Cadence code in a single transaction, with no delay and no additional authorization. If that contract:

- holds `FungibleToken.Vault` or `NonFungibleToken.NFT` resources in its account storage (e.g., a user-facing DeFi vault or escrow),
- or has been issued `Withdraw`-entitled capabilities by users who trusted the original code,

the malicious update can immediately transfer all controlled assets to the attacker. The authorized-deployers list — the only protocol-level mechanism intended to gate who may modify contracts — provides no protection once a contract exists. Removing an account from the list after deployment does not prevent it from updating its contract.

This is the direct Flow analog of the report's finding: contracts holding public funds are upgradeable by their owner immediately, with no timelock window for users to exit.

### Likelihood Explanation
The attack requires only that the malicious party owns a Flow account with a previously deployed contract. No staked-node compromise, no quorum, no leaked service-account key is needed. The attacker submits a standard user transaction with `auth(UpdateContract) &Account` for their own account. The bypass is unconditional and deterministic — it is not a race condition or probabilistic exploit. Any contract author who has deployed a contract that users have entrusted with assets can execute this immediately.

### Recommendation
1. **Apply the authorized-deployers check to updates as well as deployments.** Remove the `!exists &&` guard so that `isAuthorizedForDeployment` is evaluated for both paths, or introduce a separate `isAuthorizedForUpdate` check that consults a dedicated on-chain list.
2. **Introduce a timelock for contract updates.** Stage updates in a pending state for a configurable delay (e.g., 48 hours) before they take effect, giving users time to withdraw funds from contracts whose code is about to change.
3. **Emit a protocol-level event for every contract update** so monitoring infrastructure can alert users immediately when a contract they have interacted with is modified.

### Proof of Concept

**Attacker-controlled entry path:**

```cadence
// Step 1 (initial, when authorized): deploy a vault-holding contract
transaction {
    prepare(signer: auth(AddContract) &Account) {
        signer.contracts.add(name: "UserVault", code: "<legitimate vault code>".decodeHex())
    }
}

// Step 2 (later, after removal from authorized list): update to malicious code
// No service-account co-signature required; no timelock enforced.
transaction {
    prepare(signer: auth(UpdateContract) &Account) {
        signer.contracts.update(name: "UserVault", code: "<drain-all code>".decodeHex())
    }
}
```

The FVM processes the second transaction through `UpdateAccountContractCode` → `SetContract`. Because `ContractExists("UserVault", signer) == true`, the `isAuthorizedForDeployment` branch is never entered. The malicious code is committed at `Commit()` time with no further checks. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4)

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

**File:** fvm/environment/contract_updater.go (L320-345)
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
