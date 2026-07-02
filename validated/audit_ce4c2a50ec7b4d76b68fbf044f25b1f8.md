[1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3)

### Citations

**File:** fvm/environment/transaction_info.go (L30-38)
```go
func DefaultTransactionInfoParams() TransactionInfoParams {
	// NOTE: TxIndex, TxId and TxBody are populated by NewTransactionEnv rather
	// than by Context.
	return TransactionInfoParams{
		TransactionFeesEnabled:         false,
		LimitAccountStorage:            false,
		RandomSourceHistoryCallAllowed: false,
		EVMTestOperationsAllowed:       false,
	}
```

**File:** fvm/environment/history_random_source_provider.go (L58-60)
```go
func (b forbiddenRandomSourceHistoryProvider) RandomSourceHistory() ([]byte, error) {
	return nil, errors.NewOperationNotSupportedError("RandomSourceHistory")
}
```

**File:** fvm/environment/history_random_source_provider.go (L73-88)
```go
func NewRandomSourceHistoryProvider(
	tracer tracing.TracerSpan,
	meter Meter,
	entropyProvider EntropyProvider,
	randomSourceCallAllowed bool,
) RandomSourceHistoryProvider {
	if randomSourceCallAllowed {
		return &historySourceProvider{
			tracer:          tracer,
			meter:           meter,
			EntropyProvider: entropyProvider,
		}
	}

	return NewForbiddenRandomSourceHistoryProvider()
}
```

**File:** fvm/runtime/cadence_function_declarations.go (L42-47)
```go
			func(invocation interpreter.Invocation) interpreter.Value {
				source, err := fvmEnv.RandomSourceHistory()

				if err != nil {
					panic(err)
				}
```
