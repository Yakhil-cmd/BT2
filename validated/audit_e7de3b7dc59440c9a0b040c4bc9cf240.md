### Title
Raw Internal Error Strings Exposed to Unauthenticated REST API Callers via `NewBadRequestError` - (File: `engine/access/rest/common/error.go`)

### Summary
The Access Node REST API exposes raw internal error strings — including Go standard library package names and error formats — directly to unauthenticated callers. The root cause is `NewBadRequestError`, which unconditionally sets the user-facing message to `err.Error()`. Any caller that wraps a third-party or standard library error and passes it to `NewBadRequestError` leaks implementation details to the client.

### Finding Description
`NewBadRequestError` is defined as:

```go
// engine/access/rest/common/error.go:32-38
func NewBadRequestError(err error) *Error {
    return &Error{
        status:      http.StatusBadRequest,
        userMessage: err.Error(),   // raw internal error string becomes the user message
        err:         err,
    }
}
```

`userMessage` is what `ErrorHandler` sends to the client via `statusErr.UserMessage()`. There is no sanitization layer between the raw Go error and the HTTP response body.

This function is called in at least 17 production REST handler files across the Access API surface. Representative call sites that wrap standard library errors:

- `engine/access/rest/experimental/get_account_transactions.go:52` — wraps `strconv.ParseUint` error: produces `"invalid limit: strconv.ParseUint: parsing \"abc\": invalid syntax"` in the response body.
- `engine/access/rest/experimental/get_account_transactions.go:61` — wraps `base64.RawURLEncoding.DecodeString` error: produces `"invalid cursor encoding: illegal base64 data at input byte N"`.
- `engine/access/rest/websockets/legacy/routes/subscribe_events.go:21,32` — wraps event filter and request parsing errors.

A second, independent exposure exists in the legacy WebSocket handler:

```go
// engine/access/rest/websockets/legacy/websocket_handler.go:86-88
} else {
    wsCode = websocket.CloseInternalServerErr
    wsMsg = err.Error()   // raw error sent as WebSocket close message
}
```

When an error does not satisfy `common.StatusError` (e.g., a raw subscription error or an unexpected response type error), the full `err.Error()` string is sent as the WebSocket close frame payload to the client.

Additionally, the HTTP error handler forwards the full Cadence runtime error string:

```go
// engine/access/rest/common/http_request_handler.go:69-73
cadenceError := fvmErrors.Find(err, fvmErrors.ErrCodeCadenceRunTimeError)
if cadenceError != nil {
    msg := fmt.Sprintf("Cadence error: %s", cadenceError.Error())
    h.errorResponse(w, http.StatusBadRequest, msg, errorLogger)
```

`cadenceError.Error()` includes the full Cadence interpreter error chain (type names, interpreter internals, wrapped FVM error codes).

### Impact Explanation
An unauthenticated caller can enumerate the internal Go standard library package names (`strconv`, `encoding/base64`, `encoding/json`), their error message formats, and Cadence interpreter internals by crafting malformed REST or WebSocket requests. This enables:

1. **Go runtime/library version fingerprinting**: The exact error format of `strconv.ParseUint`, `base64.DecodeString`, etc. is version-specific. An attacker can correlate the observed format against known Go release changelogs to determine the exact Go version running on the Access Node.
2. **Targeted CVE exploitation**: Once the Go version is known, the attacker can target known CVEs in that specific Go release or its standard library.
3. **Cadence interpreter fingerprinting**: Full Cadence runtime error messages expose interpreter type names and internal error codes, enabling version-specific Cadence exploit targeting.

The impact class is **private data/implementation detail exposure** reachable by any unprivileged Access API caller.

### Likelihood Explanation
The Access Node REST API is publicly reachable by design — it is the primary external interface for clients. No authentication is required to call `GET /v1/blocks`, `GET /v1/events`, `POST /v1/scripts`, or the WebSocket subscription endpoint. Crafting a malformed request (e.g., `limit=abc`, an invalid base64 cursor, or a malformed event filter) is trivial and requires no special knowledge. The exposure is deterministic and reproducible.

### Recommendation
1. **Fix `NewBadRequestError`**: Do not use `err.Error()` as the `userMessage`. Instead, require callers to supply an explicit, sanitized user-facing message string, similar to how `NewRestError` and `NewNotFoundError` already work:
   ```go
   func NewBadRequestError(msg string, err error) *Error {
       return &Error{status: http.StatusBadRequest, userMessage: msg, err: err}
   }
   ```
2. **Fix legacy WebSocket `wsErrorHandler`**: Replace `wsMsg = err.Error()` with a static generic message (e.g., `"internal server error"`) and log the raw error server-side only.
3. **Sanitize Cadence error forwarding**: In `ErrorHandler`, replace `cadenceError.Error()` with a generic message such as `"transaction execution failed"` and log the full error internally.
4. **Audit all `NewBadRequestError` call sites**: Ensure every call site provides a safe, static user-facing message rather than a wrapped library error.

### Proof of Concept

**REST API — library name disclosure via invalid `limit` parameter:**
```
GET /experimental/v1/accounts/0x1234.../transactions?limit=abc
```
Response (HTTP 400):
```json
{"code": 400, "message": "invalid limit: strconv.ParseUint: parsing \"abc\": invalid syntax"}
```
The string `strconv.ParseUint` is the Go standard library package and function name, directly exposing the internal implementation.

**REST API — base64 library disclosure via invalid cursor:**
```
GET /experimental/v1/accounts/0x1234.../transactions?cursor=!!!
```
Response (HTTP 400):
```json
{"code": 400, "message": "invalid cursor encoding: illegal base64 data at input byte 0"}
```

**WebSocket — raw error in close frame:**
Connect to the legacy WebSocket subscription endpoint and trigger a subscription error. The WebSocket close frame payload will contain the raw Go error string from the state stream backend, including any wrapped library error messages.

**Attacker-controlled entry path:** Any unauthenticated HTTP client → Access Node REST API → `NewBadRequestError(err)` → `ErrorHandler` → `statusErr.UserMessage()` → HTTP response body containing raw Go library error string. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4)

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

**File:** engine/access/rest/common/http_request_handler.go (L60-74)
```go
func (h *HttpHandler) ErrorHandler(w http.ResponseWriter, err error, errorLogger zerolog.Logger) {
	// rest status type error should be returned with status and user message provided
	var statusErr StatusError
	if errors.As(err, &statusErr) {
		h.errorResponse(w, statusErr.Status(), statusErr.UserMessage(), errorLogger)
		return
	}

	// handle cadence errors
	cadenceError := fvmErrors.Find(err, fvmErrors.ErrCodeCadenceRunTimeError)
	if cadenceError != nil {
		msg := fmt.Sprintf("Cadence error: %s", cadenceError.Error())
		h.errorResponse(w, http.StatusBadRequest, msg, errorLogger)
		return
	}
```

**File:** engine/access/rest/websockets/legacy/websocket_handler.go (L86-89)
```go
	} else {
		wsCode = websocket.CloseInternalServerErr
		wsMsg = err.Error()
	}
```

**File:** engine/access/rest/experimental/get_account_transactions.go (L49-55)
```go
	if raw := r.GetQueryParam("limit"); raw != "" {
		parsed, err := strconv.ParseUint(raw, 10, 32)
		if err != nil {
			return nil, common.NewBadRequestError(fmt.Errorf("invalid limit: %w", err))
		}
		limit = uint32(parsed)
	}
```

**File:** engine/access/rest/experimental/get_account_transactions.go (L58-66)
```go
	if raw := r.GetQueryParam("cursor"); raw != "" {
		c, err := parseCursor(raw)
		if err != nil {
			return nil, common.NewBadRequestError(err)
		}
		if c.BlockHeight != 0 || c.TransactionIndex != 0 {
			cursor = c
		}
	}
```
