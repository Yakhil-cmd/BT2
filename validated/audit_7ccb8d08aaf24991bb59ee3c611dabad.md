### Title
Server-Side Request Forgery (SSRF) via attacker-controlled `definition` URL in payment URI parsing - (File: uri.js)

### Summary
`uri.js`'s `parseUri()` accepts Obyte/Byteball payment URIs of the form `obyte:data?app=definition&definition=https://...`. When the `definition` parameter starts with `https://`, the wallet automatically issues an outbound HTTPS request to that attacker-supplied URL via `fetchUrl()`, with no restriction on the destination host, and uses the raw response body as the address `definition`. This mirrors the reported price-feeder SSRF bug class: an untrusted, externally supplied URL is dereferenced by the node/wallet process without any allow-listing or network isolation.

### Finding Description
In `parseUri()`, when `app === 'definition'` and `assocParams.definition` begins with `https://`, the code calls `fetchUrl(definition, ...)` directly on the user/attacker-supplied string: [1](#0-0) 

`fetchUrl()` performs an unrestricted `https.get(url, ...)` request and returns the raw response body as long as the HTTP status is 200, with no validation of the destination IP/host (no protection against private/internal/link-local addresses): [2](#0-1) 

Because the URI (and therefore the `definition` URL) is fully attacker-controlled — it can be embedded in a QR code, deep link, or payment request shared with a victim — a malicious counterparty can craft a link that causes the victim's wallet process to make outbound HTTPS requests to arbitrary hosts reachable from that machine (e.g., internal admin interfaces, cloud metadata endpoints exposing IAM credentials via HTTPS proxies, or other local services), similar in kind to the pattern flagged in the price-feeder report (unauthenticated internal HTTP requests dereferenced from attacker-controlled input). The fetched response is not validated as a well-formed address definition before being placed into `assocParams.definition` and returned via `callbacks.ifOk`, so a compromised/malicious endpoint can also inject attacker-chosen "definition" content into the wallet flow.

A related, narrower-scope instance of the same "trust externally-declared URL then dereference it" pattern exists in `arbiters.js`, where the arbstore URL returned for a given `arbiter_address` (an address the wallet user chooses to contract with) is fetched via `http.get`/custom `httpRequest` with no host restriction: [3](#0-2) 

### Impact Explanation
An attacker able to get a victim to open/scan a crafted `obyte:` URI (a normal wallet interaction, not requiring any special network position) can force the victim's wallet process to issue outbound HTTPS requests to arbitrary destinations of the attacker's choosing. Depending on the victim's network environment, this can be used to probe or exfiltrate data from internal services reachable only from the wallet's host/network (SSRF), and to feed attacker-controlled response content back into the wallet's definition-processing logic. This satisfies the "AA/wallet message handling" reachable-surface category and is a concrete data-validation/SSRF weakness analogous to the reported bug class.

### Likelihood Explanation
Likelihood is moderate: it requires the victim to open a maliciously crafted payment URI (a normal, expected wallet action such as scanning a QR code from an untrusted party), and requires the wallet's network to expose some HTTPS-reachable internal resource. No special privileges, malicious peer/hub, or protocol-level compromise are needed — only crafting a URI, which is fully within reach of any unprivileged counterparty interacting with a wallet user.

### Recommendation
- Validate/allow-list the `definition` URL's host before fetching (reject private, loopback, link-local, and metadata IP ranges such as `127.0.0.0/8`, `10.0.0.0/8`, `169.254.0.0/16`, `192.168.0.0/16`, `::1`, etc.), resolving DNS first and re-checking the resolved IP.
- Disable or tightly restrict HTTP redirects in `fetchUrl()`/`httpRequest()`/`requestInfoFromArbStore()` and re-validate the destination on any redirect.
- Enforce request timeouts and response size limits (already partially present) alongside the above host validation for all HTTP(S) clients that dereference externally supplied URLs (`uri.js:fetchUrl`, `arbiters.js:requestInfoFromArbStore`, `arbiter_contract.js:httpRequest`).

### Proof of Concept
1. Attacker crafts a URI: `obyte:data?app=definition&definition=https%3A%2F%2Fattacker-controlled-host-that-resolves-to-internal-ip%2Fpath` and shares it with the victim (QR code / deep link).
2. Victim's wallet calls `parseUri()`, which detects `app === 'definition'` and `definition.substr(0,8) === 'https://'`, then calls `fetchUrl(definition, cb)`. [4](#0-3) 
3. `fetchUrl` issues an `https.get` to the attacker-chosen host with no destination validation, and on a 200 response returns the body directly into `assocParams.definition`, which is passed back to the caller via `callbacks.ifOk(objRequest)`. [5](#0-4) 
4. If the attacker controls DNS for the hostname (or uses a rebinding technique), the request can be steered to an internal address reachable from the victim's machine, achieving SSRF.

### Citations

**File:** uri.js (L124-135)
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

**File:** arbiters.js (L35-49)
```javascript
function requestInfoFromArbStore(url, cb){
	http.get(url, function(resp){
		var data = '';
		resp.on('data', function(chunk){
			data += chunk;
		});
		resp.on('end', function(){
			try {
				cb(null, JSON.parse(data));
			} catch(ex) {
				cb(ex);
			}
		});
	}).on("error", cb);
}
```
