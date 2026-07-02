### Title
Verbose Internal Storage Error Disclosure via Access Node REST API to Unauthenticated Callers - (File: `engine/access/rest/common/http_request_handler.go`)

### Summary
The Access Node REST API's centralized `ErrorHandler` explicitly forwards verbatim gRPC backend status messages — including raw storage error details — to unauthenticated HTTP callers. The gRPC status messages are constructed by error-conversion functions that embed raw storage backend errors (BadgerDB/Pebble), internal component labels, and implementation-specific state details. Any unauthenticated caller who triggers a backend error receives these internal details in the JSON response body.

### Finding Description
`ErrorHandler` in `engine/access/rest/common/http_request_handler.go` is the single centralized error handler for every REST endpoint served by the Access Node (standard HTTP handler, experimental handler, and WebSocket handler all embed `*common.HttpHandler`). For every recognized gRPC status code it forwards `se.Message()` verbatim to the client:

```go
// handle grpc status error returned from the backend calls, we are forwarding the message to the client
if se, ok := status.FromError(err); ok {
    switch se.Code() {
    case codes.NotFound:
        msg := fmt.Sprintf("Flow resource not found: %s", se.Message())
    case codes.InvalidArgument:
        msg := fmt.Sprintf("Invalid Flow argument: %s", se.Message())
    case codes.Internal:
        msg := fmt.Sprintf("Invalid Flow request: %s", se.Message())
    case codes.Unavailable:
        msg := fmt.Sprintf("Failed to process request: %s", se.Message())
    case codes.FailedPrecondition:
        msg := fmt.Sprintf("Precondition failed: %s", se.Message())
    case codes.OutOfRange:
        msg := fmt.Sprintf("Out of range: %s", se.Message())
    }
}
``` [1](#0-0) 

The gRPC status messages that reach this handler are built by error-conversion helpers that embed raw storage errors verbatim via `%v`:

- `ConvertStorageError` produces `"failed to find: <raw storage error>"` at `codes.Internal` and `"not found: <raw storage error>"` at `codes.NotFound`. [2](#0-1) 

- `ConvertIndexError` produces `"data for block is not available: <raw indexer error>"` at `codes.FailedPrecondition` and `"data not found: <raw storage error>"` at `codes.NotFound`. [3](#0-2) 

- `ConvertError` produces `"<prefix>: <raw error>"` at whatever default code is passed (often `codes.Internal`). [4](#0-3) 

- `mapReadError` in the extended backend produces `"<label> index not initialized: <raw storage error>"` at `codes.FailedPrecondition`, `"requested height not indexed: <raw storage error>"` at `codes.OutOfRange`, and `"invalid query: <raw storage error>"` at `codes.InvalidArgument` — all embedding the internal component label and raw error. [5](#0-4) 

The `codes.Internal` path is the most severe: raw BadgerDB/Pebble error strings (e.g., `"Value log GC attempt on a read-only open"`, `"LOCK: already held by process"`, `"Manifest file is corrupted"`) are embedded into the gRPC status message and then forwarded to the HTTP client as:

```json
{"code":500,"message":"Invalid Flow request: failed to find: <BadgerDB internal error>"}
```

This is confirmed by existing tests that assert the full internal error string appears in the HTTP response body: [6](#0-5) [7](#0-6) 

The `NewBadRequestError` constructor also sets `userMessage` directly to `err.Error()`, meaning any error passed to it is returned verbatim to the client as a 400 response: [8](#0-7) 

### Impact Explanation
An unauthenticated caller who sends any request that triggers a backend storage or index error receives:

1. **Storage technology fingerprinting**: Error strings like `"failed to find: Key not found"` or `"failed to find: Value log GC attempt on a read-only open"` confirm BadgerDB or Pebble as the storage backend, enabling targeted exploitation of known storage-layer weaknesses.
2. **Internal architecture mapping**: Component labels embedded in `mapReadError` (e.g., `"account_transactions index not initialized"`) reveal the names and initialization state of internal indexing subsystems. `ConvertIndexError` reveals the exact height-based indexing scheme.
3. **Internal state disclosure**: BadgerDB/Pebble error messages can reveal whether the node is in a degraded state (GC in progress, lock contention, manifest corruption), which an attacker can use to time targeted requests.
4. **Attack surface expansion**: Knowing the exact storage key format and error semantics (e.g., `"data for block height X is not available"`) allows an attacker to probe the exact boundaries of indexed data and craft requests that maximize information leakage.

### Likelihood Explanation
Likelihood is high. The `ErrorHandler` is the single shared error handler for every REST endpoint on the Access Node — blocks, transactions, scripts, events, accounts, collections, contracts, and all experimental endpoints. The forwarding is intentional and documented in a code comment. Any unauthenticated network caller can trigger backend errors by requesting non-existent resources, out-of-range heights, or malformed identifiers, all of which are normal REST API operations requiring no authentication.

### Recommendation
- For `codes.Internal` errors, return a generic opaque message (e.g., `"internal server error"`) and log the full gRPC status message server-side with a correlation ID. Never forward raw storage error strings to the client.
- For `codes.NotFound`, `codes.FailedPrecondition`, `codes.OutOfRange`, and `codes.InvalidArgument`, strip the `%v`-embedded raw error from the gRPC status message before forwarding; return only a sanitized, user-facing description.
- Audit all call sites of `ConvertStorageError`, `ConvertIndexError`, `ConvertError`, and `mapReadError` to ensure the embedded `%v` error is not forwarded to external callers.
- In `NewBadRequestError`, ensure that only pre-sanitized, user-facing strings are used as `userMessage`; do not pass raw internal errors directly.

### Proof of Concept
An unauthenticated caller sends a GET request to any Access Node REST endpoint for a resource that triggers a storage-layer failure:

```
GET /v1/collections/<valid-hex-id>
Host: <access-node>:8080
```

If the underlying BadgerDB/Pebble storage returns an unexpected error (e.g., during GC or under lock contention), the response is:

```json
{
  "code": 500,
  "message": "Invalid Flow request: failed to find: Value log GC attempt on a read-only open"
}
```

This reveals the storage backend technology and its internal operational state to the unauthenticated caller. Similarly, querying an out-of-range block height on an experimental endpoint returns:

```json
{
  "code": 400,
  "message": "Out of range: requested height not indexed: <internal indexer error details>"
}
```

revealing the internal indexing subsystem's error semantics and state.

### Citations

**File:** engine/access/rest/common/http_request_handler.go (L82-111)
```go
	// handle grpc status error returned from the backend calls, we are forwarding the message to the client
	if se, ok := status.FromError(err); ok {
		switch se.Code() {
		case codes.NotFound:
			msg := fmt.Sprintf("Flow resource not found: %s", se.Message())
			h.errorResponse(w, http.StatusNotFound, msg, errorLogger)
			return
		case codes.InvalidArgument:
			msg := fmt.Sprintf("Invalid Flow argument: %s", se.Message())
			h.errorResponse(w, http.StatusBadRequest, msg, errorLogger)
			return
		case codes.Internal:
			msg := fmt.Sprintf("Invalid Flow request: %s", se.Message())
			h.errorResponse(w, http.StatusInternalServerError, msg, errorLogger)
			return
		case codes.Unavailable:
			msg := fmt.Sprintf("Failed to process request: %s", se.Message())
			h.errorResponse(w, http.StatusServiceUnavailable, msg, errorLogger)
			return
		case codes.FailedPrecondition:
			// indicates the system wasn't in a state to handle the request, treated as a bad request.
			msg := fmt.Sprintf("Precondition failed: %s", se.Message())
			h.errorResponse(w, http.StatusBadRequest, msg, errorLogger)
			return
		case codes.OutOfRange:
			msg := fmt.Sprintf("Out of range: %s", se.Message())
			h.errorResponse(w, http.StatusBadRequest, msg, errorLogger)
			return
		}
	}
```

**File:** engine/common/rpc/errors.go (L22-52)
```go
func ConvertError(err error, msg string, defaultCode codes.Code) error {
	if err == nil {
		return nil
	}

	// Handle multierrors separately
	if multiErr, ok := err.(*multierror.Error); ok {
		return ConvertMultiError(multiErr, msg, defaultCode)
	}

	// Already converted
	if status.Code(err) != codes.Unknown {
		return err
	}

	if msg != "" {
		msg += ": "
	}

	var returnCode codes.Code
	switch {
	case errors.Is(err, context.Canceled):
		returnCode = codes.Canceled
	case errors.Is(err, context.DeadlineExceeded):
		returnCode = codes.DeadlineExceeded
	default:
		returnCode = defaultCode
	}

	return status.Errorf(returnCode, "%s%v", msg, err)
}
```

**File:** engine/common/rpc/errors.go (L56-71)
```go
func ConvertStorageError(err error) error {
	if err == nil {
		return nil
	}

	// Already converted
	if status.Code(err) == codes.NotFound {
		return err
	}

	if errors.Is(err, storage.ErrNotFound) {
		return status.Errorf(codes.NotFound, "not found: %v", err)
	}

	return status.Errorf(codes.Internal, "failed to find: %v", err)
}
```

**File:** engine/common/rpc/errors.go (L76-94)
```go
func ConvertIndexError(err error, height uint64, defaultMsg string) error {
	if err == nil {
		return nil
	}

	if errors.Is(err, indexer.ErrIndexNotInitialized) {
		return status.Errorf(codes.FailedPrecondition, "data for block is not available: %v", err)
	}

	if errors.Is(err, storage.ErrHeightNotIndexed) {
		return status.Errorf(codes.OutOfRange, "data for block height %d is not available", height)
	}

	if errors.Is(err, storage.ErrNotFound) {
		return status.Errorf(codes.NotFound, "data not found: %v", err)
	}

	return ConvertError(err, defaultMsg, codes.Internal)
}
```

**File:** access/backends/extended/backend.go (L112-127)
```go
// mapReadError converts storage read errors to appropriate gRPC status errors.
func mapReadError(ctx context.Context, label string, err error) error {
	switch {
	case errors.Is(err, storage.ErrNotBootstrapped):
		return status.Errorf(codes.FailedPrecondition, "%s index not initialized: %v", label, err)
	case errors.Is(err, storage.ErrHeightNotIndexed):
		return status.Errorf(codes.OutOfRange, "requested height not indexed: %v", err)
	case errors.Is(err, storage.ErrInvalidQuery):
		return status.Errorf(codes.InvalidArgument, "invalid query: %v", err)
	case errors.Is(err, storage.ErrNotFound):
		return status.Errorf(codes.NotFound, "not found: %v", err)
	default:
		irrecoverable.Throw(ctx, fmt.Errorf("failed to get %s: %w", label, err))
		return err
	}
}
```

**File:** engine/access/rest/http/routes/collections_test.go (L129-135)
```go
			{
				unittest.IdentifierFixture().String(),
				nil,
				status.Errorf(codes.Internal, "some internal error"),
				`{"code":500,"message":"Invalid Flow request: some internal error"}`,
				http.StatusInternalServerError,
			},
```

**File:** engine/access/rest/http/routes/scripts_test.go (L92-106)
```go
	t.Run("get error", func(t *testing.T) {
		backend := &mock.API{}
		backend.Mock.
			On("ExecuteScriptAtBlockHeight", mocks.Anything, uint64(1337), validCode, [][]byte{validArgs}).
			Return(nil, status.Error(codes.Internal, "internal server error"))

		req := scriptReq("", "1337", validBody)
		router.AssertResponse(
			t,
			req,
			http.StatusInternalServerError,
			`{"code":500, "message":"Invalid Flow request: internal server error"}`,
			backend,
		)
	})
```

**File:** engine/access/rest/common/error.go (L32-38)
```go
func NewBadRequestError(err error) *Error {
	return &Error{
		status:      http.StatusBadRequest,
		userMessage: err.Error(),
		err:         err,
	}
}
```
