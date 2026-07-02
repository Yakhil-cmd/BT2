### Title
Stale Indexed-Height Balance Check in `checkSufficientBalanceToPayForTransaction` Causes False Positive Transaction Rejection — (`File: access/validator/validator.go`)

---

### Summary

`TransactionValidator.checkSufficientBalanceToPayForTransaction` evaluates the payer's FLOW balance against a potentially stale indexed state (up to `DefaultSealedIndexedHeightThreshold = 30` blocks behind the sealed chain head). When the payer's balance was recently topped up within that lag window, the check observes a lower-than-actual balance and returns `InsufficientBalanceError`. With `CheckPayerBalanceMode == EnforceCheck`, the Access Node hard-rejects the transaction even though the payer has sufficient funds at the current chain state.

---

### Finding Description

`checkSufficientBalanceToPayForTransaction` in `access/validator/validator.go` performs the following sequence:

1. Fetches the latest sealed block height (`sealedHeight`).
2. Fetches `indexedHeight` from the index reporter.
3. Allows the gap `sealedHeight − indexedHeight` to be up to `DefaultSealedIndexedHeightThreshold = 30` blocks before bailing out with `IndexedHeightFarBehindError` (which is silently swallowed and does **not** reject the transaction).
4. Executes `verifyPayerBalanceScript` **at `indexedHeight`**, not at the sealed tip.
5. If the script returns `canExecuteTransaction = false`, returns `InsufficientBalanceError`. [1](#0-0) 

In `Validate()`, an `InsufficientBalanceError` with `EnforceCheck` mode causes a hard rejection: [2](#0-1) 

The constant that defines the tolerated staleness window: [3](#0-2) 

**The inaccuracy**: if the payer received FLOW tokens in any of the up-to-30 blocks between `indexedHeight` and `sealedHeight`, the script sees the pre-deposit balance. The check therefore reports "insufficient balance" for a payer who actually has enough funds at the current sealed state — a direct analog to checking `msg.sender.balance` after ETH has already been sent.

---

### Impact Explanation

Any unprivileged transaction sender whose FLOW balance was increased within the last ≤30 sealed blocks (e.g., they just received tokens from another account) will have their transaction hard-rejected by any Access Node running in `EnforceCheck` mode. The rejection is indistinguishable from a genuine insufficient-balance case: [4](#0-3) 

The user receives an `InsufficientBalanceError` and cannot submit the transaction through that Access Node, even though the Execution Node would accept and execute it successfully. The user's funds are not at risk, but their ability to transact is incorrectly blocked — matching the original report's impact of preventing a user with sufficient funds from completing a legitimate operation.

---

### Likelihood Explanation

- `EnforceCheck` mode is a supported, documented, production configuration option for Access Nodes.
- The 30-block lag window is always present during normal operation; indexing routinely lags sealing by several blocks.
- Any user who receives FLOW tokens and immediately submits a transaction (a common pattern: receive tokens, then spend them) falls into this window.
- The entry path requires only a standard, unprivileged transaction submission — no special privileges, no key compromise, no staked node control.

---

### Recommendation

Replace the stale indexed-height balance evaluation with one of the following:

1. **Use the sealed height directly**: execute `verifyPayerBalanceScript` at `sealedHeight` instead of `indexedHeight`, so the check reflects the most recent sealed state.
2. **Reduce the tolerance window**: lower `DefaultSealedIndexedHeightThreshold` to 0 or 1, so the stale-state window is negligible.
3. **Treat `IndexedHeightFarBehindError` as a skip, not a silent pass**: the current code already silently skips the check when the gap is too large; apply the same logic when the gap is non-zero and the result is a rejection, to avoid false positives. [5](#0-4) 

---

### Proof of Concept

**Scenario**:

1. Payer account `P` has balance `B < requiredFee` at sealed block `N` (indexed height = `N`).
2. At sealed block `N+1`, account `P` receives a token transfer bringing its balance to `B' > requiredFee`. Indexed height is still `N` (lag = 1 block, well within the 30-block threshold).
3. Payer `P` submits a transaction to an Access Node with `CheckPayerBalanceMode = EnforceCheck`.
4. `checkSufficientBalanceToPayForTransaction` executes `verifyPayerBalanceScript` at `indexedHeight = N`, observing balance `B < requiredFee`.
5. Returns `InsufficientBalanceError{Payer: P, RequiredBalance: requiredFee}`.
6. `Validate()` returns this error; the Access Node rejects the transaction.
7. The Execution Node, operating on the actual sealed state at block `N+1`, would have accepted and executed the transaction successfully. [6](#0-5) [7](#0-6)

### Citations

**File:** access/validator/validator.go (L29-31)
```go
// DefaultSealedIndexedHeightThreshold is the default number of blocks between sealed and indexed height
// this sets a limit on how far into the past the payer validator will allow for checking the payer's balance.
const DefaultSealedIndexedHeightThreshold = 30
```

**File:** access/validator/validator.go (L248-261)
```go
	err = v.checkSufficientBalanceToPayForTransaction(ctx, tx)
	if err != nil {
		// we only return InsufficientBalanceError as it's a client-side issue
		// that requires action from a user. Other errors (e.g. parsing errors)
		// are 'internal' and related to script execution process. they shouldn't
		// prevent the transaction from proceeding.
		if IsInsufficientBalanceError(err) {
			v.transactionValidationMetrics.TransactionValidationFailed(metrics.InsufficientBalance)

			if v.options.CheckPayerBalanceMode == EnforceCheck {
				log.Warn().Err(err).Str("transactionID", tx.ID().String()).Str("payerAddress", tx.Payer.String()).Msg("enforce check error")
				return err
			}
		}
```

**File:** access/validator/validator.go (L528-581)
```go
func (v *TransactionValidator) checkSufficientBalanceToPayForTransaction(ctx context.Context, tx *flow.TransactionBody) error {
	if v.options.CheckPayerBalanceMode == Disabled {
		return nil
	}

	header, err := v.blocks.SealedHeader()
	if err != nil {
		return fmt.Errorf("could not fetch block header: %w", err)
	}

	indexedHeight, err := v.blocks.IndexedHeight()
	if err != nil {
		return fmt.Errorf("could not get indexed height: %w", err)
	}

	// we use latest indexed block to get the most up-to-date state data available for executing scripts.
	// check here to make sure indexing is within an acceptable tolerance of sealing to avoid issues
	// if indexing falls behind
	sealedHeight := header.Height
	if indexedHeight < sealedHeight-DefaultSealedIndexedHeightThreshold {
		return IndexedHeightFarBehindError{SealedHeight: sealedHeight, IndexedHeight: indexedHeight}
	}

	payerAddress := cadence.NewAddress(tx.Payer)
	inclusionEffort := cadence.UFix64(tx.InclusionEffort())
	gasLimit := cadence.UFix64(tx.GasLimit)

	args, err := cadenceutils.EncodeArgs([]cadence.Value{payerAddress, inclusionEffort, gasLimit})
	if err != nil {
		return fmt.Errorf("failed to encode cadence args for script executor: %w", err)
	}

	result, err := v.scriptExecutor.ExecuteAtBlockHeight(ctx, v.verifyPayerBalanceScript, args, indexedHeight)
	if err != nil {
		return fmt.Errorf("script finished with error: %w", err)
	}

	value, err := jsoncdc.Decode(nil, result)
	if err != nil {
		return fmt.Errorf("could not decode result value returned by script executor: %w", err)
	}

	canExecuteTransaction, requiredBalance, _, err := fvm.DecodeVerifyPayerBalanceResult(value)
	if err != nil {
		return fmt.Errorf("could not parse cadence value returned by script executor: %w", err)
	}

	// return no error if payer has sufficient balance
	if canExecuteTransaction {
		return nil
	}

	return InsufficientBalanceError{Payer: tx.Payer, RequiredBalance: requiredBalance}
}
```

**File:** access/validator/errors.go (L138-146)
```go
type InsufficientBalanceError struct {
	Payer           flow.Address
	RequiredBalance cadence.UFix64
}

func (e InsufficientBalanceError) Error() string {
	return fmt.Sprintf("transaction payer (%s) has insufficient balance to pay transaction fee. "+
		"Required balance: (%s). ", e.Payer, e.RequiredBalance.String())
}
```
