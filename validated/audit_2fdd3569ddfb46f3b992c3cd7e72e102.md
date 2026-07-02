### Title
Missing Account Existence Check in Extended API Backends Returns Empty Success for Non-Existent Accounts - (`access/backends/extended/backend_account_transfers.go`, `access/backends/extended/backend_account_transactions.go`)

---

### Summary

`GetAccountTransactions`, `GetAccountFungibleTokenTransfers`, and `GetAccountNonFungibleTokenTransfers` in the extended API backends only validate that a supplied address is format-valid for the chain, but never verify that the account actually exists on-chain. The documented API contract in `api.go` explicitly promises `codes.NotFound` when the account is not found. The missing check is acknowledged by `// TODO: check if account exists for the chain` comments left in the production code. Any unprivileged API caller supplying a format-valid but non-existent address receives a successful empty response instead of the specified error, violating the API contract.

---

### Finding Description

The `API` interface in `api.go` documents the following contract for all three methods:

```
// Expected error returns during normal operations:
//   - [codes.NotFound] if the account is not found
``` [1](#0-0) [2](#0-1) [3](#0-2) 

In `GetAccountTransactions`, the only guard is a format check:

```go
if !b.chain.IsValid(address) {
    return nil, status.Errorf(codes.NotFound, "account %s is not valid on chain %s", ...)
}
// TODO: check if account exists for the chain
``` [4](#0-3) 

`b.chain.IsValid(address)` validates only that the address bytes are structurally valid for the chain (e.g., within the address space), not that the account has ever been created. A format-valid but never-created address passes this guard and proceeds to query the index, returning an empty success page.

The same pattern appears in both transfer backends:

```go
if !b.chain.IsValid(address) {
    return nil, status.Errorf(codes.NotFound, "account %s is not valid on chain %s", ...)
}
// ...
// TODO: check if account exists for the chain
``` [5](#0-4) [6](#0-5) [7](#0-6) [8](#0-7) 

The `// TODO: check if account exists for the chain` comments in production code confirm the existence check was intentionally deferred and never implemented.

---

### Impact Explanation

Any unprivileged caller of the extended Access API (reachable via gRPC or REST) can supply a format-valid but non-existent Flow address and receive a successful empty-list response instead of `codes.NotFound`. This violates the documented API contract, making it impossible for callers to distinguish between:

- "Account exists but has no recorded activity" (legitimate empty result), and
- "Account does not exist" (should be `NotFound`).

Systems and integrations that rely on the `NotFound` signal to detect non-existent accounts — for example, to gate downstream logic, display account status, or validate user input — will silently misclassify non-existent accounts as existing-but-inactive. This is the direct analog of the ERC-721 `tokenURI` violation: the specification/contract promises an error for non-existent entities, but the implementation silently returns empty data instead.

---

### Likelihood Explanation

The entry path requires no privileges: any caller with access to the extended API endpoint can trigger this by providing any format-valid address that has never been created on-chain. Flow addresses are short (8 bytes), and the valid address space is large, so there are many non-existent but format-valid addresses. The `// TODO` comments confirm this is a known, unresolved gap in production code.

---

### Recommendation

Before querying the index, verify that the account exists in the protocol state (e.g., via the execution state or account storage). Return `status.Errorf(codes.NotFound, ...)` if the account does not exist, fulfilling the contract already documented in `api.go`. The `// TODO: check if account exists for the chain` comments mark the exact insertion points in all three backends.

---

### Proof of Concept

1. Obtain any format-valid Flow address that has never been created on-chain (e.g., `0x0000000000000001` on a network where that address was never initialized).
2. Call `GetAccountTransactions` (or `GetAccountFungibleTokenTransfers` / `GetAccountNonFungibleTokenTransfers`) via the extended API with that address.
3. Observe: the call returns HTTP 200 / `codes.OK` with an empty `transactions` (or `transfers`) array and no error.
4. Expected per the documented contract: `codes.NotFound` — "account not found."

The root cause is the missing account existence check at:
- [4](#0-3) 
- [5](#0-4) 
- [7](#0-6)

### Citations

**File:** access/backends/extended/api.go (L19-22)
```go
	// Expected error returns during normal operations:
	//   - [codes.NotFound] if the account is not found
	//   - [codes.FailedPrecondition] if the account transaction index has not been initialized
	//   - [codes.OutOfRange] if the cursor references a height outside the indexed range
```

**File:** access/backends/extended/api.go (L39-42)
```go
	// Expected error returns during normal operations:
	//   - [codes.NotFound] if the account is not found
	//   - [codes.FailedPrecondition] if the fungible token transfer index has not been initialized
	//   - [codes.OutOfRange] if the cursor references a height outside the indexed range
```

**File:** access/backends/extended/api.go (L59-62)
```go
	// Expected error returns during normal operations:
	//   - [codes.NotFound] if the account is not found
	//   - [codes.FailedPrecondition] if the non-fungible token transfer index has not been initialized
	//   - [codes.OutOfRange] if the cursor references a height outside the indexed range
```

**File:** access/backends/extended/backend_account_transactions.go (L101-104)
```go
	if !b.chain.IsValid(address) {
		return nil, status.Errorf(codes.NotFound, "account %s is not valid on chain %s", address, b.chain.ChainID())
	}
	// TODO: check if account exists for the chain
```

**File:** access/backends/extended/backend_account_transfers.go (L145-147)
```go
	if !b.chain.IsValid(address) {
		return nil, status.Errorf(codes.NotFound, "account %s is not valid on chain %s", address, b.chain.ChainID())
	}
```

**File:** access/backends/extended/backend_account_transfers.go (L166-167)
```go
	// TODO: check if account exists for the chain
	for i := range page.Transfers {
```

**File:** access/backends/extended/backend_account_transfers.go (L214-216)
```go
	if !b.chain.IsValid(address) {
		return nil, status.Errorf(codes.NotFound, "account %s is not valid on chain %s", address, b.chain.ChainID())
	}
```

**File:** access/backends/extended/backend_account_transfers.go (L235-236)
```go
	// TODO: check if account exists for the chain
	for i := range page.Transfers {
```
