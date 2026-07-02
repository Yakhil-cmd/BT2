### Title
Raw Internal Error Strings Sent to WebSocket Clients in Close Frames - (File: engine/access/rest/websockets/legacy/websocket_handler.go)

### Summary
The legacy WebSocket handler's `wsErrorHandler` function sends raw, unfiltered `err.Error()` strings directly to connecting clients in WebSocket close frames whenever an error does not implement the `common.StatusError` interface. Multiple internal error paths — including subscription backend errors, type assertion failures, and I/O errors — produce plain `fmt.Errorf` errors that bypass the safe `StatusError` path and expose internal details to any unprivileged caller.

### Finding Description
In `wsErrorHandler`, the error dispatch logic is:

```go
if errors.As(err, &statusErr) {
    wsMsg = statusErr.UserMessage()   // safe: controlled message
} else {
    wsCode = websocket.CloseInternalServerErr
    wsMsg = err.Error()               // unsafe: raw internal string
}
// sent directly to the client
wsController.conn.WriteControl(websocket.CloseMessage,
    websocket.FormatCloseMessage(wsCode, wsMsg), ...)
``` [1](#0-0) 

Only errors that implement `common.StatusError` receive a sanitized `UserMessage()`. All other errors — including every plain `fmt.Errorf` call in `writeEvents` — fall into the `else` branch and have their full `.Error()` string transmitted to the client.

The callers that produce non-`StatusError` errors and therefore leak raw strings include:

1. **Subscription backend error** (line 121): `fmt.Errorf("stream encountered an error: %v", sub.Err())` — wraps the raw subscription error, which may contain storage layer details, execution node error messages, or internal state information. [2](#0-1) 

2. **Type assertion failure** (line 137): `fmt.Errorf("unexpected response type: %s", event)` — exposes internal Go type names. [3](#0-2) 

3. **CCF-to-JSON conversion failure** (line 156): `fmt.Errorf("could not convert event payload from CCF to Json: %w", err)` — wraps the underlying codec error. [4](#0-3) 

4. **Raw I/O errors** from `conn.WriteJSON` and `conn.WriteMessage` (lines 178, 188) are passed directly without wrapping. [5](#0-4) 

Additionally, `NewBadRequestError` in the shared error helper unconditionally sets `userMessage: err.Error()`, meaning the raw underlying error string becomes the user-facing message for every bad-request error across all REST routes. [6](#0-5) 

### Impact Explanation
An unprivileged caller who opens a WebSocket connection to the legacy event-subscription endpoint and triggers any of the above error paths receives the raw internal error string in the WebSocket RFC 6455 close frame. Depending on which error fires, this can reveal:

- Internal storage error messages (e.g., `storage.ErrNotFound` wrapped with file/key context from the execution node)
- Internal Go type names and memory representations
- Codec/serialization error details that hint at internal data formats
- Network-level I/O error strings that may include internal addresses or connection state

This is a direct analog to the reported `JsonResponse({"error": str(e)})` pattern: raw exception text is returned to the caller instead of a generic message.

### Likelihood Explanation
The legacy WebSocket endpoint (`/v1/subscribe_events`) is publicly reachable by any Access API caller without authentication. Triggering a subscription error (e.g., by subscribing at a pruned or unavailable block height) is straightforward and requires no special privileges. The `sub.Err()` path is exercised whenever the backend subscription channel closes with an error, which is a normal operational occurrence.

### Recommendation
- In `wsErrorHandler`, replace the `else` branch with a generic message: `wsMsg = "internal server error"` and log the raw error server-side only.
- Remove the raw `err.Error()` from `NewBadRequestError`'s `userMessage` field; instead pass a caller-controlled safe string and keep the raw error only in the internal `err` field for logging.
- Audit all `fmt.Errorf` calls passed to `wsErrorHandler` to ensure they either implement `StatusError` with a safe `UserMessage()` or are replaced with sentinel errors.

### Proof of Concept
1. Connect to the legacy WebSocket endpoint: `ws://<access-node>/v1/subscribe_events?start_block_height=<pruned_height>&event_types=A.X.Y.Z`
2. The backend subscription will close with an error when the requested height is not available.
3. `writeEvents` constructs `fmt.Errorf("stream encountered an error: %v", sub.Err())` — a plain error, not a `StatusError`.
4. `wsErrorHandler` enters the `else` branch, sets `wsMsg = err.Error()`, and sends the full string in the WebSocket close frame.
5. The client reads the close frame and observes the raw internal error message, e.g.: `"stream encountered an error: failed to get events: block height 42 is not indexed"`.

### Citations

**File:** engine/access/rest/websockets/legacy/websocket_handler.go (L86-92)
```go
	} else {
		wsCode = websocket.CloseInternalServerErr
		wsMsg = err.Error()
	}

	// Close the connection with the CloseError message
	err = wsController.conn.WriteControl(websocket.CloseMessage, websocket.FormatCloseMessage(wsCode, wsMsg), time.Now().Add(time.Second))
```

**File:** engine/access/rest/websockets/legacy/websocket_handler.go (L120-123)
```go
				if sub.Err() != nil {
					err := fmt.Errorf("stream encountered an error: %v", sub.Err())
					wsController.wsErrorHandler(err)
					return
```

**File:** engine/access/rest/websockets/legacy/websocket_handler.go (L136-139)
```go
			if !ok {
				err = fmt.Errorf("unexpected response type: %s", event)
				wsController.wsErrorHandler(err)
				return
```

**File:** engine/access/rest/websockets/legacy/websocket_handler.go (L154-158)
```go
				payload, err := convert.CcfPayloadToJsonPayload(e.Payload)
				if err != nil {
					err = fmt.Errorf("could not convert event payload from CCF to Json: %w", err)
					wsController.wsErrorHandler(err)
					return
```

**File:** engine/access/rest/websockets/legacy/websocket_handler.go (L177-190)
```go
			err = wsController.conn.WriteJSON(event)
			if err != nil {
				wsController.wsErrorHandler(err)
				return
			}
		case <-ticker.C:
			err := wsController.conn.SetWriteDeadline(time.Now().Add(websockets.WriteWait))
			if err != nil {
				wsController.wsErrorHandler(common.NewRestError(http.StatusInternalServerError, "failed to set the initial write deadline: ", err))
				return
			}
			if err := wsController.conn.WriteMessage(websocket.PingMessage, nil); err != nil {
				wsController.wsErrorHandler(err)
				return
```

**File:** engine/access/rest/common/error.go (L32-37)
```go
func NewBadRequestError(err error) *Error {
	return &Error{
		status:      http.StatusBadRequest,
		userMessage: err.Error(),
		err:         err,
	}
```
