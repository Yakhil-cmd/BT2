## Analog Found

### Title
Server-Side Request Forgery via unvalidated `definition` URL fetch in `parseUri` - (File: uri.js)

### Summary
`uri.js` implements `parseUri()`, the routine used by Obyte/ocore wallets to interpret `byteball:`/`obyte:` deep links, including payment-request links sent by a chat peer (e.g. a private-payment counterparty during address/definition exchange). When the link encodes `app=definition` and the `definition` parameter starts with `https://`, the wallet does not treat this string as an actual address definition — instead it blindly performs an outbound HTTP GET to that attacker-controlled URL via `fetchUrl()`, and stashes the raw response body into `assocParams.definition` before returning the parsed request to the caller.

### Finding Description
In `parseUri`, the `app === 'definition'` branch reads the `definition` query parameter straight from the incoming URI without any allow-listing, protocol restriction (beyond a bare `https://` string check), or destination validation (no block on private/loopback IP ranges, link-local addresses, cloud metadata endpoints, etc.): [1](#0-0) 

The fetch itself is performed by `fetchUrl()`, a thin wrapper around Node's `https.get`, which follows the caller-supplied host/port/path verbatim: [2](#0-1) 

Any party able to hand the victim a crafted `byteball:data?app=definition&definition=https://...` string — for example a chat/pairing counterparty sending a link, or a device-message flow that surfaces such a URI to be opened — can force the recipient wallet process to issue an HTTP request to an arbitrary internal or external host chosen by the attacker. This mirrors the CVE-2024-1021 pattern: a URL taken from untrusted input is passed directly into an HTTP client function (`readRawText`-equivalent is `fetchUrl`) with no destination validation.

### Impact Explanation
A successful SSRF here lets a remote, unprivileged counterparty (anyone who can hand the victim a link during pairing/payment negotiation) cause the victim's wallet process to make outbound requests to internal-only services (e.g. `127.0.0.1`, RFC1918 ranges, or cloud metadata IPs reachable from the host running the wallet/hub), potentially exfiltrating internal service responses back into the parsed request object, or being used to port-scan/probe internal infrastructure from the victim's network position. Because the fetched body is inserted into `assocParams.definition`, if any caller subsequently treats that string as an address/definition (rather than raw JSON validated separately), it opens a secondary path to trick the wallet into acting on attacker-supplied "definition" content.

### Likelihood Explanation
The trigger is a single crafted URI string, requiring no cryptographic material, unit posting, or special privilege — any peer capable of sending a chat message/pairing link that gets parsed by `parseUri` can attempt it. The only precondition is that some wallet flow calls `parseUri` on attacker-influenced input (e.g., payment-request/definition-exchange links exchanged with a private-payment counterparty), which is the designed use of this function.

### Recommendation
- Do not fetch arbitrary URLs supplied via untrusted deep links. If remote-hosted definitions must be supported, resolve the hostname and reject requests to private/loopback/link-local/metadata address ranges, enforce a strict scheme/port allow-list, add request timeouts, and cap response size.
- Alternatively, require that `definition` always be inline JSON (never a URL) for content originating from another party, and only allow the URL-fetch convenience for locally-typed/local file input.

### Proof of Concept
1. Attacker sends the victim wallet a link (via chat/pairing or QR) of the form:
   `byteball:data?app=definition&definition=https://169.254.169.254/latest/meta-data/iam/security-credentials/`
   (or any internal host/port the attacker wants to probe).
2. Victim wallet calls `parseUri()` on this string.
3. `main_part === 'data'` and `app === 'definition'` with `definition.substr(0,8) === 'https://'` triggers `fetchUrl(definition, ...)`.
4. `fetchUrl` performs `https.get(url, ...)`, issuing the request from the victim's network context and returning the response body, which is written into `assocParams.definition` and passed back via `callbacks.ifOk(objRequest)`.

### Citations

**File:** uri.js (L124-136)
```javascript
		if (app === 'definition') {
			var definition = assocParams.definition;
			if (!definition)
				return callbacks.ifError("no definition");
			if (definition.substr(0, 8) === 'https://') {
				return fetchUrl(definition, function (err, response) {
					if (err)
						return callbacks.ifError(err);
					assocParams.definition = response;
					callbacks.ifOk(objRequest);
				});
			}
		}
```

**File:** uri.js (L251-291)
```javascript
function fetchUrl(url, cb) {
	var https = require('https');
	var bDone = false;
	function returnError(err) {
		console.log(err);
		if (bDone)
			return;
		bDone = true;
		cb(err);
	}
	try {
		https.get(url, function (resp) {
			if (resp.statusCode !== 200)
				return returnError("non-200 response while trying to fetch " + url);
			var data = '';

			// A chunk of data has been recieved.
			resp.on('data', function(chunk) {
				data += chunk;
			});

			// aborted before the whole response has been received
			resp.on('aborted', function () {
				returnError("connection aborted while trying to fetch " + url);
			});

			// The whole response has been received
			resp.on('end', function () {
				if (bDone)
					return;
				bDone = true;
				cb(null, data);
			});
		}).on("error", function(err) {
			returnError("non-200 response while trying to fetch " + url + ": " + err.message);
		});
	}
	catch(err) {
		returnError(err.message);
	}
}
```
