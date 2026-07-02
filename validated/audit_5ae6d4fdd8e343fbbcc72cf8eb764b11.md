### Title
Raw Internal Error Messages Exposed to Unprivileged API Callers via REST and WebSocket Error Handlers - (File: `engine/access/rest/common/error.go`, `engine/access/rest/common/http_request_handler.go`, `engine/access/rest/websockets/legacy/websocket_handler.go`)

---

### Summary

The Flow Access REST API and legacy WebSocket handler expose raw internal error strings directly to unauthenticated callers. `NewBadRequestError` sets the user-facing message to `err.Error()` verbatim, and `ErrorHandler` forwards the full gRPC status message (including internal backend error details) for every recognized gRPC error code. The legacy WebSocket error handler additionally sends `err.Error()` directly in the WebSocket close frame for any error that is not a `StatusError`. Any unprivileged caller can trigger these paths by sending crafted requests.

---

### Finding Description

**Location 1 — `NewBadRequestError` (`engine/access/rest/common/error.go:32-38`)**

```go
func NewBadRequestError(err error) *Error {
    return &Error{
        status:      http.StatusBadRequest,
        userMessage: err.Error(),   // raw error string becomes the user-facing message
        err:         err,
    }
}
```

`userMessage` is the field returned to the HTTP client. It is set to `err.Error()` unconditionally. This function is called from every REST route handler on request-parsing failure: [1](#0-0) 

It is invoked across all REST endpoints including `ExecuteScript`, `GetAccount`, `GetEvents`, `CreateTransaction`, `GetBlocksByHeight`, and more: [2](#0-1) [3](#0-2) 

**Location 2 — `ErrorHandler` gRPC message forwarding (`engine/access/rest/common/http_request_handler.go:83-110`)**

For every recognized gRPC status code, the full `se.Message()` from the backend is embedded in the HTTP response body and returned to the caller:

```go
case codes.Internal:
    msg := fmt.Sprintf("Invalid Flow request: %s", se.Message())
    h.errorResponse(w, http.StatusInternalServerError, msg, errorLogger)
```

The gRPC messages are produced by `ConvertError` / `ConvertStorageError` / `ConvertIndexError`, which embed the full Go error chain (e.g., `"failed to select execution nodes: <multierror with EN addresses>"`, `"failed to find: <storage key details>"`): [4](#0-3) [5](#0-4) 

**Location 3 — `wsErrorHandler` raw error in WebSocket close frame (`engine/access/rest/websockets/legacy/websocket_handler.go:86-89`)**

For any error that is not a `StatusError`, the raw `err.Error()` string is sent directly to the client as the WebSocket close message:

```go
} else {
    wsCode = websocket.CloseInternalServerErr
    wsMsg = err.Error()   // raw internal error sent to client
}
``` [6](#0-5) 

Errors reaching this branch include subscription failures (`"stream encountered an error: <sub.Err()>"`), unexpected response types, and CCF conversion failures — all of which can carry internal implementation details: [7](#0-6) 

---

### Impact Explanation

Internal error strings returned to callers can include:
- Execution node network addresses and identity strings (from `CallAvailableNode` multierrors)
- Storage key/path details from BadgerDB or Pebble error messages
- Internal error chains revealing function names, module paths, and state details (e.g., `"failed to get transaction result: <storage layer error>"`)

This information helps an attacker map the internal topology of the Access node's backend (which execution nodes it contacts, what storage keys exist), identify exploitable edge cases, and craft more targeted follow-up requests. [8](#0-7) 

---

### Likelihood Explanation

The Access REST API and legacy WebSocket endpoint are publicly reachable by any unprivileged caller — no staking, authentication, or special capability is required. An attacker can trivially trigger error paths by:
- Sending requests with valid-format but non-existent block IDs or transaction IDs
- Sending requests that reference blocks not yet executed (triggering `codes.Internal` from the EN backend)
- Opening a WebSocket subscription and causing a subscription failure

All three code paths are exercised in normal operation and require no special privileges.

---

### Recommendation

1. **`NewBadRequestError`**: Accept a separate `userMessage string` parameter (as `NewNotFoundError` and `NewRestError` already do) and pass a generic message like `"invalid request parameters"` as the user-facing string; log the raw `err` server-side only.
2. **`ErrorHandler`**: For `codes.Internal` (and optionally `codes.Unavailable`), replace `se.Message()` with a static generic string (e.g., `"internal server error"`); log the full message server-side.
3. **`wsErrorHandler`**: In the `else` branch, replace `wsMsg = err.Error()` with a static string (e.g., `"internal error"`); log the raw error server-side.

---

### Proof of Concept

```
# Trigger a codes.Internal backend error via the REST API
# (request a transaction result for a block that exists but has not been executed)
curl -s "https://<access-node>/v1/transactions/<valid-tx-id>/results" \
  -H "Accept: application/json"

# Response body will contain the full gRPC status message, e.g.:
# {"code":500,"message":"Invalid Flow request: failed to retrieve result from any
#  execution node: 2 errors occurred:\n\t* rpc error: code = Unavailable desc =
#  connection refused (execution-node-1.internal:9000)\n\t* rpc error: ..."}
```

The response leaks internal execution node addresses and the full error chain from `ConvertMultiError`, directly analogous to the `JsonResponse({"error": str(e)})` pattern in the reference report. [9](#0-8) [10](#0-9)

### Citations

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

**File:** engine/access/rest/http/routes/scripts.go (L13-16)
```go
	req, err := request.GetScriptRequest(r)
	if err != nil {
		return nil, common.NewBadRequestError(err)
	}
```

**File:** engine/access/rest/http/routes/transactions.go (L25-28)
```go
	req, err := request.GetTransactionRequest(r)
	if err != nil {
		return nil, common.NewBadRequestError(err)
	}
```

**File:** engine/access/rest/common/http_request_handler.go (L82-110)
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
```

**File:** engine/common/rpc/errors.go (L47-51)
```go
	default:
		returnCode = defaultCode
	}

	return status.Errorf(returnCode, "%s%v", msg, err)
```

**File:** engine/common/rpc/errors.go (L96-138)
```go
// ConvertMultiError converts a multierror to a grpc status error.
// If the errors have related status codes, the common code is returned, otherwise defaultCode is used.
func ConvertMultiError(err *multierror.Error, msg string, defaultCode codes.Code) error {
	allErrors := err.WrappedErrors()
	if len(allErrors) == 0 {
		return nil
	}

	if msg != "" {
		msg += ": "
	}

	// get a list of all of status codes
	allCodes := make(map[codes.Code]struct{})
	for _, err := range allErrors {
		allCodes[status.Code(err)] = struct{}{}
	}

	// if they all match, return that
	if len(allCodes) == 1 {
		code := status.Code(allErrors[0])
		return status.Errorf(code, "%s%v", msg, err)
	}

	// if they mostly match, ignore Unavailable and DeadlineExceeded since any other code is
	// more descriptive
	if len(allCodes) == 2 {
		if _, ok := allCodes[codes.Unavailable]; ok {
			delete(allCodes, codes.Unavailable)
			for code := range allCodes {
				return status.Errorf(code, "%s%v", msg, err)
			}
		}
		if _, ok := allCodes[codes.DeadlineExceeded]; ok {
			delete(allCodes, codes.DeadlineExceeded)
			for code := range allCodes {
				return status.Errorf(code, "%s%v", msg, err)
			}
		}
	}

	// otherwise, return the default code
	return status.Errorf(defaultCode, "%s%v", msg, err)
```

**File:** engine/access/rest/websockets/legacy/websocket_handler.go (L86-89)
```go
	} else {
		wsCode = websocket.CloseInternalServerErr
		wsMsg = err.Error()
	}
```

**File:** engine/access/rest/websockets/legacy/websocket_handler.go (L119-140)
```go
			if !ok {
				if sub.Err() != nil {
					err := fmt.Errorf("stream encountered an error: %v", sub.Err())
					wsController.wsErrorHandler(err)
					return
				}
				err := fmt.Errorf("subscription channel closed, no error occurred")
				wsController.wsErrorHandler(common.NewRestError(http.StatusRequestTimeout, "subscription channel closed", err))
				return
			}
			err := wsController.conn.SetWriteDeadline(time.Now().Add(websockets.WriteWait))
			if err != nil {
				wsController.wsErrorHandler(common.NewRestError(http.StatusInternalServerError, "failed to set the initial write deadline: ", err))
				return
			}

			resp, ok := event.(*backend.EventsResponse)
			if !ok {
				err = fmt.Errorf("unexpected response type: %s", event)
				wsController.wsErrorHandler(err)
				return
			}
```

**File:** engine/access/rpc/backend/transactions/error_messages/provider.go (L137-141)
```go
	if err != nil {
		if common.IsInsufficientExecutionReceipts(err) {
			return "", status.Error(codes.NotFound, err.Error())
		}
		return "", rpc.ConvertError(err, "failed to select execution nodes", codes.Internal)
```
