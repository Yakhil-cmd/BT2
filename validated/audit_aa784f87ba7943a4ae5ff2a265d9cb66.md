### Title
Attacker-Controlled Cadence Runtime Error Messages Reflected Verbatim to REST API Clients — (File: `engine/access/rest/common/http_request_handler.go`)

### Summary
The Access Node REST API's `ErrorHandler` directly injects unsanitized Cadence runtime error message strings — which are fully controlled by any unprivileged Cadence contract or script author — into HTTP JSON error responses returned to API clients. This is a direct structural analog to the ZecWallet finding: attacker-controlled data from a remote source is reflected verbatim into a user-facing interface with no filtering or substitution.

### Finding Description
In `engine/access/rest/common/http_request_handler.go`, the `ErrorHandler` function handles Cadence runtime errors as follows:

```go
// handle cadence errors
cadenceError := fvmErrors.Find(err, fvmErrors.ErrCodeCadenceRunTimeError)
if cadenceError != nil {
    msg := fmt.Sprintf("Cadence error: %s", cadenceError.Error())
    h.errorResponse(w, http.StatusBadRequest, msg, errorLogger)
    return
}
``` [1](#0-0) 

The `cadenceError.Error()` string originates from the Cadence runtime interpreter. Cadence's `panic()` and `assert()` built-ins, as well as any runtime error message produced by a contract, flow through `NewCadenceRuntimeError` in `fvm/errors/execution.go`: [2](#0-1) 

and are wrapped by `WrappedCadenceRuntime` before reaching the REST layer: [3](#0-2) 

The resulting error string — which is entirely authored by the Cadence contract or script — is then formatted into the HTTP response body with no sanitization, truncation, or substitution with a pre-arranged code.

Additionally, the same `ErrorHandler` explicitly forwards raw gRPC status message strings from backend calls to the client across all handled status codes:

```go
// handle grpc status error returned from the backend calls, we are forwarding the message to the client
if se, ok := status.FromError(err); ok {
    switch se.Code() {
    case codes.NotFound:
        msg := fmt.Sprintf("Flow resource not found: %s", se.Message())
``` [4](#0-3) 

The `errorResponse` method serializes this string directly into the `ModelError.Message` field of the JSON response body: [5](#0-4) 

### Impact Explanation
A malicious Cadence contract author — requiring no privileged access, only the ability to deploy a contract on-chain — can embed arbitrary text in contract panic messages or assertion failure strings. When a legitimate user's application calls the REST API (`ExecuteScriptAt*`, `GetTransactionResult`, etc.) and the execution path hits the malicious contract, the REST API returns a `400 Bad Request` JSON body whose `message` field contains the attacker's verbatim string, prefixed only with `"Cadence error: "`. An application that surfaces this message to end users (e.g., a wallet UI, a dApp frontend, a block explorer) will display the attacker-crafted text as if it were a legitimate system error. This enables phishing payloads (e.g., fake "update your wallet" instructions with a malicious URL) to be delivered through the trusted Access Node REST API surface, matching the original report's exploit scenario exactly.

### Likelihood Explanation
Deploying a Cadence contract is a standard, permissionless operation on Flow mainnet. Any account holder can deploy a contract containing `panic("Your wallet is outdated. Download the fix at https://attacker.example/update")`. Any user whose application calls a script that touches this contract — including indirect calls through composability — will receive the crafted message in the REST API response. Wallet applications and dApp frontends routinely display Cadence error messages to help users debug failed transactions, making the social-engineering surface realistic and not hypothetical.

### Recommendation
**Short term:** Replace the direct `cadenceError.Error()` interpolation with a static, pre-arranged message such as `"script execution failed with a Cadence runtime error"` and log the full error server-side only. Apply the same treatment to the gRPC `se.Message()` forwarding paths — substitute with static strings keyed on the status code rather than forwarding the raw backend message.

**Long term:** Establish a policy that no string originating from user-submitted Cadence code or from a remote node's gRPC status message is ever interpolated into a user-facing API response body. Introduce a linting or review gate that flags any `fmt.Sprintf` that mixes a fixed prefix with an `err.Error()` or `se.Message()` call in a response-writing path.

### Proof of Concept
1. Deploy a Cadence contract on Flow mainnet:
   ```cadence
   pub contract Phish {
       pub fun run() {
           panic("URGENT: Your wallet requires an update. Visit https://attacker.example/update to secure your funds.")
       }
   }
   ```
2. Submit a REST API call to `POST /v1/scripts` with a script body that calls `Phish.run()`.
3. The Access Node REST API returns:
   ```json
   {
     "code": 400,
     "message": "Cadence error: error caused by: URGENT: Your wallet requires an update. Visit https://attacker.example/update to secure your funds."
   }
   ```
4. Any wallet or dApp frontend that displays this `message` field to the end user delivers the attacker's phishing payload through the legitimate Access Node REST API endpoint, with no network interception required.

The root cause is confirmed at: [1](#0-0)

### Citations

**File:** engine/access/rest/common/http_request_handler.go (L68-74)
```go
	// handle cadence errors
	cadenceError := fvmErrors.Find(err, fvmErrors.ErrCodeCadenceRunTimeError)
	if cadenceError != nil {
		msg := fmt.Sprintf("Cadence error: %s", cadenceError.Error())
		h.errorResponse(w, http.StatusBadRequest, msg, errorLogger)
		return
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

**File:** engine/access/rest/common/http_request_handler.go (L147-158)
```go
func (h *HttpHandler) errorResponse(
	w http.ResponseWriter,
	returnCode int,
	responseMessage string,
	logger zerolog.Logger,
) {
	// create error response model
	modelError := models.ModelError{
		Code:    int32(returnCode),
		Message: responseMessage,
	}
	h.JsonResponse(w, returnCode, modelError, logger)
```

**File:** fvm/errors/execution.go (L22-27)
```go
func NewCadenceRuntimeError(err runtime.Error) CodedError {
	return WrapCodedError(
		ErrCodeCadenceRunTimeError,
		err,
		"cadence runtime error")
}
```

**File:** fvm/runtime/wrapped_cadence_runtime.go (L25-28)
```go
func (wr WrappedCadenceRuntime) ExecuteScript(s runtime.Script, c runtime.Context) (cadence.Value, error) {
	v, err := wr.Runtime.ExecuteScript(s, c)
	return v, errors.HandleRuntimeError(err)
}
```
