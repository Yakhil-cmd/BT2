### Title
Interface Signature Mismatch: `access.API.GetScheduledTransaction` Silently Shadowed by `extended.API.GetScheduledTransaction` — (`access/api.go`, `access/backends/extended/api.go`, `engine/access/rest/http/routes/transactions.go`)

---

### Summary

The `access.API` interface and the `access/backends/extended` package both declare a method named `GetScheduledTransaction`, but with **incompatible signatures and return types**. The REST handler dispatches calls through `access.API`, which resolves to the embedded `UnimplementedAPI.GetScheduledTransaction` stub (returning `codes.Unimplemented`) rather than the extended backend's real implementation. Any user calling the REST scheduled-transaction endpoint against an Access Node that uses the extended backend receives a permanent "method not implemented" error.

---

### Finding Description

**Interface 1 — `access.TransactionsAPI` (embedded in `access.API`):**

```go
// access/api.go:63
GetScheduledTransaction(ctx context.Context, scheduledTxID uint64) (*flow.TransactionBody, error)
```

**Interface 2 — `access/backends/extended.API`:**

```go
// access/backends/extended/api.go:79-84
GetScheduledTransaction(
    ctx context.Context,
    id uint64,
    expandOptions ScheduledTransactionExpandOptions,
    encodingVersion entities.EventEncodingVersion,
) (*accessmodel.ScheduledTransaction, error)
```

These two interfaces share the method name `GetScheduledTransaction` but differ in **arity** (2 vs 4 parameters) and **return type** (`*flow.TransactionBody` vs `*accessmodel.ScheduledTransaction`). In Go, a concrete type cannot satisfy both simultaneously; it can only have one method with a given name.

The extended backend (`ScheduledTransactionsBackend`) implements the 4-parameter variant:

```go
// access/backends/extended/backend_scheduled_transactions.go:140-145
func (b *ScheduledTransactionsBackend) GetScheduledTransaction(
    ctx context.Context,
    id uint64,
    expandOptions ScheduledTransactionExpandOptions,
    encodingVersion entities.EventEncodingVersion,
) (*accessmodel.ScheduledTransaction, error)
```

This method does **not** satisfy `access.API.GetScheduledTransaction`. To compile as `access.API`, the extended backend must embed a type that provides the 2-parameter variant — the only available candidate is `UnimplementedAPI`:

```go
// access/unimplemented.go:149-151
func (u *UnimplementedAPI) GetScheduledTransaction(ctx context.Context, scheduledTxID uint64) (*flow.TransactionBody, error) {
    return nil, status.Error(codes.Unimplemented, "method GetScheduledTransaction not implemented")
}
```

The REST handler dispatches through `access.API`:

```go
// engine/access/rest/http/routes/transactions.go:186
tx, err := backend.GetScheduledTransaction(r.Context(), req.ScheduledTxID)
```

Because Go method dispatch is resolved by the **exact** method signature, this call resolves to the embedded `UnimplementedAPI.GetScheduledTransaction` (2-parameter), not the extended backend's 4-parameter implementation. The extended backend's real logic is unreachable through `access.API`.

---

### Impact Explanation

Every REST request to `GET /v1/transactions/{scheduledTxID}` (where the ID is a numeric scheduled-transaction ID) is routed through `GetScheduledTransaction` in `routes/transactions.go`. When the Access Node uses the extended backend, this call permanently returns `codes.Unimplemented`. The scheduled-transaction REST endpoint is **permanently broken** for all users of that node — no scheduled transaction can ever be retrieved via REST. The `GetScheduledTransactionResult` endpoint suffers the same fate if the same pattern applies to `GetScheduledTransactionResult`.

---

### Likelihood Explanation

The extended backend is the production implementation for Access Nodes with execution-state indexing enabled. Any operator deploying such a node exposes this broken endpoint to all clients. No special attacker capability is required — any unprivileged API caller sending a valid `GET /v1/transactions/{numericID}` request triggers the failure path.

---

### Recommendation

1. **Align the `access.API` interface** with the extended backend's richer signature, or introduce a distinct method name (e.g., `GetScheduledTransactionExpanded`) to avoid the collision.
2. **Add a compile-time assertion** in the extended backend package: `var _ access.API = (*ExtendedBackend)(nil)` so that any future signature drift is caught at build time.
3. **Update the REST handler** to accept the extended API interface when the extended backend is in use, so that `expandOptions` and `encodingVersion` are forwarded correctly.

---

### Proof of Concept

1. Deploy an Access Node with execution-state indexing enabled (extended backend active).
2. Send: `GET /v1/transactions/1` (numeric ID → routed to `GetScheduledTransaction`).
3. The call resolves to `UnimplementedAPI.GetScheduledTransaction` → returns `codes.Unimplemented`.
4. The extended backend's `ScheduledTransactionsBackend.GetScheduledTransaction` (4-parameter) is never invoked.

**Root cause chain:** [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4)

### Citations

**File:** access/api.go (L63-64)
```go
	GetScheduledTransaction(ctx context.Context, scheduledTxID uint64) (*flow.TransactionBody, error)
	GetScheduledTransactionResult(ctx context.Context, scheduledTxID uint64, encodingVersion entities.EventEncodingVersion) (*accessmodel.TransactionResult, error)
```

**File:** access/backends/extended/api.go (L79-84)
```go
	GetScheduledTransaction(
		ctx context.Context,
		id uint64,
		expandOptions ScheduledTransactionExpandOptions,
		encodingVersion entities.EventEncodingVersion,
	) (*accessmodel.ScheduledTransaction, error)
```

**File:** access/backends/extended/backend_scheduled_transactions.go (L140-145)
```go
func (b *ScheduledTransactionsBackend) GetScheduledTransaction(
	ctx context.Context,
	id uint64,
	expandOptions ScheduledTransactionExpandOptions,
	encodingVersion entities.EventEncodingVersion,
) (*accessmodel.ScheduledTransaction, error) {
```

**File:** access/unimplemented.go (L149-151)
```go
func (u *UnimplementedAPI) GetScheduledTransaction(ctx context.Context, scheduledTxID uint64) (*flow.TransactionBody, error) {
	return nil, status.Error(codes.Unimplemented, "method GetScheduledTransaction not implemented")
}
```

**File:** engine/access/rest/http/routes/transactions.go (L180-201)
```go
func GetScheduledTransaction(r *common.Request, backend access.API, link commonmodels.LinkGenerator) (any, error) {
	req, err := request.NewGetScheduledTransaction(r)
	if err != nil {
		return nil, common.NewBadRequestError(err)
	}

	tx, err := backend.GetScheduledTransaction(r.Context(), req.ScheduledTxID)
	if err != nil {
		return nil, err
	}

	var txr *accessmodel.TransactionResult
	if req.ExpandsResult {
		txr, err = backend.GetScheduledTransactionResult(r.Context(), req.ScheduledTxID, entitiesproto.EventEncodingVersion_JSON_CDC_V0)
		if err != nil {
			return nil, err
		}
	}

	var response commonmodels.Transaction
	response.Build(tx, txr, link)
	return response, nil
```
