### Title
`TransactionBody.InclusionEffort()` Under-Charges Large Transactions Due to Hardcoded Constant — (File: `model/flow/transaction.go`)

---

### Summary

`TransactionBody.InclusionEffort()` always returns a hardcoded constant `100_000_000` (1.0 UFix64) regardless of the actual transaction byte size. The function's own comment acknowledges this is a placeholder. Meanwhile, `ByteSize()` correctly computes the actual transaction size but is never consulted. Every transaction — from a 100-byte no-op to a maximally-sized 1.5 MB script — pays the same inclusion fee, causing systematic under-charging for large transactions.

---

### Finding Description

In `model/flow/transaction.go`, `InclusionEffort()` is defined as:

```go
func (tb TransactionBody) InclusionEffort() uint64 {
    // Hardcoded inclusion effort (of 1.0 UFix).
    // Eventually this will be dynamic and will depend on the transaction properties
    inclusionEffort := uint64(100_000_000)
    return inclusionEffort
}
``` [1](#0-0) 

The comment explicitly states the value *should* be dynamic and depend on transaction properties. The same file already implements `ByteSize()`, which correctly accounts for script length, argument sizes, number of authorizers, and signature sizes:

```go
func (tb TransactionBody) ByteSize() uint {
    size += len(tb.Script)
    for _, arg := range tb.Arguments { size += len(arg) }
    size += len(tb.Authorizers) * AddressLength
    // ... signatures ...
}
``` [2](#0-1) 

`InclusionEffort()` is the sole input to the inclusion-fee component of every transaction fee deduction. It is called in three production paths:

1. **Actual fee deduction** — `fvm/transactionInvoker.go` passes it directly to `DeductTransactionFees`: [3](#0-2) 

2. **Pre-execution payer balance check** — `fvm/transactionPayerBalanceChecker.go` uses it to verify the payer can afford the transaction: [4](#0-3) 

3. **Access node ingress validation** — `access/validator/validator.go` uses it when checking payer balance before accepting a transaction: [5](#0-4) 

The fee formula is `inclusionFee = surgeFactor × inclusionEffortCost × inclusionEffort`. With `inclusionEffort` permanently fixed at `1.0`, the inclusion fee is identical for every transaction regardless of size.

---

### Impact Explanation

Any unprivileged transaction sender can submit a maximally-sized transaction (up to the network's `MaxTransactionByteSize` limit, typically ~1.5 MB) and pay only the minimum inclusion fee — the same fee as a 100-byte transaction. The inclusion fee is intended to compensate for the bandwidth and processing cost of including a transaction in a collection. Large transactions consume proportionally more resources (network bandwidth, collection node memory, block payload space) but are charged as if they were the smallest possible transaction. This is a direct protocol revenue leak: heavy users (bots, aggregators, contract deployers with large scripts) can minimize their operational costs by exploiting the flat inclusion fee.

---

### Likelihood Explanation

Exploitation requires no special privileges, no leaked keys, and no compromised nodes. Any account holder can submit a transaction with a large script or many large arguments. The entry path is the standard transaction submission API available to all users. The `ByteSize()` function already exists and computes the correct value, confirming the design intent was always to use it — the hardcoded constant is an unfinished placeholder that has been left in production code.

---

### Recommendation

Replace the hardcoded constant in `InclusionEffort()` with a value derived from `ByteSize()`, normalizing against a reference transaction size so that the existing `inclusionEffortCost` parameter retains its meaning:

```go
func (tb TransactionBody) InclusionEffort() uint64 {
    // Scale effort proportionally to transaction byte size.
    // 1.0 UFix64 (100_000_000) corresponds to a reference size of, e.g., 1000 bytes.
    const referenceSize = uint64(1000)
    size := uint64(tb.ByteSize())
    if size == 0 {
        size = 1
    }
    return (size * uint64(100_000_000)) / referenceSize
}
```

The exact scaling factor should be chosen to match the protocol's economic model, but the key fix is that `InclusionEffort()` must consume `ByteSize()` rather than returning a constant.

---

### Proof of Concept

```
// Attacker submits a transaction with a 500 KB Cadence script.
// ByteSize() ≈ 500_000 bytes.
// InclusionEffort() returns 100_000_000 (1.0 UFix64) — same as a 100-byte tx.
//
// Inclusion fee charged = surgeFactor × inclusionEffortCost × 1.0
//                       = 1.0 × 0.00001 × 1.0 = 0.00001 FLOW
//
// A correctly-sized fee would be:
//   = 1.0 × 0.00001 × (500_000 / 1_000) = 0.005 FLOW
//
// Under-charge factor: 500×
// Any bot submitting large contract-deployment transactions pays
// the same inclusion fee as a trivial token transfer.
```

### Citations

**File:** model/flow/transaction.go (L110-128)
```go
func (tb TransactionBody) ByteSize() uint {
	size := 0
	size += len(tb.ReferenceBlockID)
	size += len(tb.Script)
	for _, arg := range tb.Arguments {
		size += len(arg)
	}
	size += 8 // gas size
	size += tb.ProposalKey.ByteSize()
	size += AddressLength                       // payer address
	size += len(tb.Authorizers) * AddressLength // Authorizers
	for _, s := range tb.PayloadSignatures {
		size += s.ByteSize()
	}
	for _, s := range tb.EnvelopeSignatures {
		size += s.ByteSize()
	}
	return uint(size)
}
```

**File:** model/flow/transaction.go (L130-136)
```go
// InclusionEffort returns the inclusion effort of the transaction
func (tb TransactionBody) InclusionEffort() uint64 {
	// Hardcoded inclusion effort (of 1.0 UFix).
	// Eventually this will be dynamic and will depend on the transaction properties
	inclusionEffort := uint64(100_000_000)
	return inclusionEffort
}
```

**File:** fvm/transactionInvoker.go (L288-291)
```go
	_, err = executor.env.DeductTransactionFees(
		executor.proc.Transaction.Payer,
		executor.proc.Transaction.InclusionEffort(),
		computationUsed)
```

**File:** fvm/transactionPayerBalanceChecker.go (L79-83)
```go
		resultValue, err = env.CheckPayerBalanceAndGetMaxTxFees(
			proc.Transaction.Payer,
			proc.Transaction.InclusionEffort(),
			uint64(txnState.TotalComputationLimit()),
		)
```

**File:** access/validator/validator.go (L551-553)
```go
	payerAddress := cadence.NewAddress(tx.Payer)
	inclusionEffort := cadence.UFix64(tx.InclusionEffort())
	gasLimit := cadence.UFix64(tx.GasLimit)
```
