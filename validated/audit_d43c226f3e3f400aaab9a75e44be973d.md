### Title
Overly-Strict Storage Capacity Check Uses `maxTxFees` Instead of Actual Fees, Causing Legitimate Transactions to Fail - (File: `fvm/transactionInvoker.go`)

### Summary

In `normalExecution()`, the payer's storage capacity is checked using `maxTxFees` (fees for the full declared gas limit) as the reserved amount. However, actual fees deducted later are based on `computationUsed` (actual computation consumed), which is always ≤ the gas limit. When a user sets a high gas limit but uses little gas, the storage check can fail even though the payer would have sufficient storage capacity after actual fee deduction.

### Finding Description

In `fvm/transactionInvoker.go`, `normalExecution()` executes in this order:

1. `CheckPayerBalanceAndReturnMaxFees` — passes `TotalComputationLimit()` (the full declared gas limit) as `maxExecutionEffort`, returning `maxTxFees` = fees for the full gas limit.
2. Execute transaction body.
3. `CheckStorageLimits` — passes `maxTxFees` to reduce the payer's effective balance for storage capacity calculation.
4. `deductTransactionFees` — deducts fees based on `computationUsed` (actual computation used, ≤ gas limit).

The storage capacity check at step 3 uses `maxTxFees` (worst-case, pre-execution estimate) to reduce the payer's effective balance. But at this point — after step 2 — the actual computation used is already known via `executor.env.ComputationUsed()`. The actual fees that will be deducted in step 4 are strictly ≤ `maxTxFees`.

If a payer's balance is borderline, the storage check can fail with `maxTxFees` while it would pass with actual fees. The transaction is then rejected via `errorExecution()`, which still deducts fees from the payer.

This is structurally identical to the Symmio bug: a check uses a worse-case value (market price / full gas limit fees) when only the actual execution value (close price / actual computation fees) is relevant, causing a legitimate operation to fail and the user to lose funds.

### Impact Explanation

A user who:
- Has a balance borderline for storage capacity, AND
- Sets a gas limit significantly higher than actual computation usage (common practice as a safety margin)

will have their transaction fail with `StorageCapacityExceeded` even though the transaction would succeed if the storage check used actual fees. The user still loses fees via `errorExecution()` and their intended transaction effects are reverted. This is a direct financial loss and failed legitimate operation.

### Likelihood Explanation

Users routinely set gas limits higher than actual usage as a safety margin. Accounts with balances near the minimum storage reservation threshold (e.g., newly created accounts with minimal FLOW) are particularly susceptible. Any unprivileged transaction sender can trigger this by submitting a transaction with a high `GasLimit` and low actual computation usage.

### Recommendation

After transaction body execution (step 2), compute actual fees using `executor.env.ComputationUsed()` and pass the resulting actual fee amount to `CheckStorageLimits` instead of `maxTxFees`. Since execution has already completed at that point, the actual computation used is deterministically known.

### Proof of Concept

**Vulnerable code path in `fvm/transactionInvoker.go`:**

```
normalExecution():
  maxTxFees = CheckPayerBalanceAndReturnMaxFees(... TotalComputationLimit() ...)
  // maxTxFees = fee_rate × GasLimit  (worst case)

  txnBodyExecutor.Execute()
  // actual computationUsed << GasLimit

  CheckStorageLimits(..., payer, maxTxFees)
  // payer's effective balance = balance - maxTxFees  ← TOO LOW
  // capacity = f(balance - maxTxFees)  ← FAILS

  deductTransactionFees()
  // actual deduction = fee_rate × computationUsed  << maxTxFees
  // payer's real post-fee balance = balance - actualFees  ← WOULD PASS
```

**Concrete scenario:**
- Payer balance: 0.001 FLOW (just above minimum storage reservation)
- Gas limit: 9999 (high, as safety margin)
- Actual computation used: 100
- `maxTxFees` = fees for 9999 gas → reduces effective balance below storage threshold → `StorageCapacityExceeded`
- Actual fees = fees for 100 gas → effective balance remains above storage threshold → should succeed

The storage check at line 386–391 of `fvm/transactionInvoker.go` uses `maxTxFees` from line 334, but actual fees deducted at line 398 use `computationUsed` from `deductTransactionFees()` at line 276–291. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4)

### Citations

**File:** fvm/transactionInvoker.go (L269-299)
```go
func (executor *transactionExecutor) deductTransactionFees() (err error) {
	if !executor.env.TransactionFeesEnabled() {
		return nil
	}

	computationLimit := executor.txnState.TotalComputationLimit()

	computationUsed, err := executor.env.ComputationUsed()
	if err != nil {
		return errors.NewTransactionFeeDeductionFailedError(
			executor.proc.Transaction.Payer,
			computationLimit,
			err)
	}

	if computationUsed > computationLimit {
		computationUsed = computationLimit
	}

	_, err = executor.env.DeductTransactionFees(
		executor.proc.Transaction.Payer,
		executor.proc.Transaction.InclusionEffort(),
		computationUsed)

	if err != nil {
		return errors.NewTransactionFeeDeductionFailedError(
			executor.proc.Transaction.Payer,
			computationUsed,
			err)
	}
	return nil
```

**File:** fvm/transactionInvoker.go (L330-391)
```go
	var maxTxFees uint64
	// run with limits disabled since this is a static cost check
	// and should be accounted for in the inclusion cost.
	executor.txnState.RunWithMeteringDisabled(func() {
		maxTxFees, err = executor.CheckPayerBalanceAndReturnMaxFees(
			executor.proc,
			executor.txnState,
			executor.env)
	})

	if err != nil {
		return
	}

	var bodyTxnId state.NestedTransactionId
	bodyTxnId, err = executor.txnState.BeginNestedTransaction()
	if err != nil {
		return
	}

	err = executor.txnBodyExecutor.Execute()
	if err != nil {
		err = fmt.Errorf("transaction execute failed: %w", err)
		return
	}

	// Before checking storage limits, we must apply all pending changes
	// that may modify storage usage.
	var contractUpdates environment.ContractUpdates
	contractUpdates, err = executor.env.FlushPendingUpdates()
	if err != nil {
		err = fmt.Errorf(
			"transaction invocation failed to flush pending changes from "+
				"environment: %w",
			err)
		return
	}

	var bodySnapshot *snapshot.ExecutionSnapshot
	bodySnapshot, err = executor.txnState.CommitNestedTransaction(bodyTxnId)
	if err != nil {
		return
	}

	invalidator = environment.NewDerivedDataInvalidator(
		contractUpdates,
		bodySnapshot,
		executor.executionStateRead,
	)

	// Check if all account storage limits are ok
	//
	// The storage limit check is performed for all accounts that were touched during the transaction.
	// The storage capacity of an account depends on its balance and should be higher than the accounts storage used.
	// The payer account is special cased in this check and its balance is considered max_fees lower than its
	// actual balance, for the purpose of calculating storage capacity, because the payer will have to pay for this tx.
	err = executor.CheckStorageLimits(
		executor.ctx,
		executor.env,
		bodySnapshot,
		executor.proc.Transaction.Payer,
		maxTxFees)
```

**File:** fvm/transactionPayerBalanceChecker.go (L79-83)
```go
		resultValue, err = env.CheckPayerBalanceAndGetMaxTxFees(
			proc.Transaction.Payer,
			proc.Transaction.InclusionEffort(),
			uint64(txnState.TotalComputationLimit()),
		)
```

**File:** fvm/transactionStorageLimiter.go (L29-54)
```go
// CheckStorageLimits checks each account that had its storage written to during a transaction, that its storage used
// is less than its storage capacity.
// Storage used is an FVM register and is easily accessible.
// Storage capacity is calculated by the FlowStorageFees contract from the account's flow balance.
//
// The payers balance is considered to be maxTxFees lower that its actual balance, due to the fact that
// the fee deduction step happens after the storage limit check.
func (limiter TransactionStorageLimiter) CheckStorageLimits(
	ctx Context,
	env environment.Environment,
	snapshot *snapshot.ExecutionSnapshot,
	payer flow.Address,
	maxTxFees uint64,
) error {
	if !env.LimitAccountStorage() {
		return nil
	}

	defer env.StartChildSpan(trace.FVMTransactionStorageUsedCheck).End()

	err := limiter.checkStorageLimits(ctx, env, snapshot, payer, maxTxFees)
	if err != nil {
		return fmt.Errorf("storage limit check failed: %w", err)
	}
	return nil
}
```

**File:** fvm/transactionStorageLimiter.go (L130-134)
```go
	result, invokeErr := env.AccountsStorageCapacity(
		addresses,
		payer,
		maxTxFees,
	)
```
