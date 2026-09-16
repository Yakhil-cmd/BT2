## Title
Unbounded HTTP response body read in `fetchUrl()` when resolving a `definition` URL from an attacker-controlled `obyte:`/`byteball:` payment/data URI - (File: `uri.js`)

### Summary
`uri.js`'s `parseUri()` function accepts application-level `obyte:`/`byteball:` URIs (as produced by payment requests, QR codes, and links shared by any counterparty, including untrusted third parties). When the URI encodes a `data` request with `app=definition` and a `definition` value that starts with `https://`, `parseUri()` calls `fetchUrl()` to resolve the address definition from that attacker-supplied URL. [1](#0-0) 

`fetchUrl()` performs an `https.get()` and accumulates the entire response body into a single in-memory string with no upper bound on size, mirroring the exact bug class described in the OneCollector advisory (CWE-770, unbounded resource consumption reading an HTTP response body): [2](#0-1) 

### Finding Description
Any party who can get a victim to parse a URI they crafted — a payment counterparty sending a `obyte:data?app=definition&definition=https://attacker.example/huge` payment/definition link, a textcoin/chat link, or a QR code — controls the `definition` URL end-to-end. Because `main_part === 'data'` only requires that `app` be one of the allowed values and, for `app === 'definition'`, only checks that the string starts with `https://` before calling `fetchUrl`, an attacker fully controls the target host: [3](#0-2) 

Inside `fetchUrl`, the response handler concatenates every chunk onto a JS string (`data += chunk`) until the `end` event fires, with no limit on total bytes, no timeout on the transfer, and no check of `Content-Length`: [4](#0-3) 

An attacker-controlled or MITM'd HTTPS endpoint can stream an arbitrarily large (or effectively infinite, via chunked transfer) response, causing unbounded heap growth in the process that parses the URI.

### Impact Explanation
This is a memory-exhaustion / denial-of-service vector against the process running the wallet/library code that calls `parseUri` (e.g., a GUI/light wallet). Sustained large-body reads inflate the JS string held by `data`, causing severe GC pressure and, ultimately, an `OutOfMemoryException`/crash, taking the local node/wallet process down and preventing it from confirming/processing units until restarted — consistent with the "network/process unable to operate" outcome called out in the validation criteria. No signature or trust check gates the `definition` value before the fetch is performed, so the trigger is reachable by any counterparty who can hand the victim a URI (payment request, textcoin, pairing/attestation flow, or website link).

### Likelihood Explanation
Likelihood is moderate: it requires the victim to open/parse a maliciously crafted `obyte:`/`byteball:` URI whose `app=definition` value points to an attacker-controlled `https://` endpoint (or an on-path attacker able to serve a huge body for a legitimate-looking URL). This is a normal, low-friction interaction pattern (clicking a payment link, scanning a QR code, or receiving a link in chat), so a counterparty with no special privileges can reach this code path with a single crafted string.

### Recommendation
In `fetchUrl()` (`uri.js`), cap the number of bytes read from the response (e.g., abort/destroy the response stream once accumulated `data.length` exceeds a fixed limit such as a few hundred KB, since a definition is expected to be small JSON), enforce a request/response timeout, and validate `Content-Length` against the same cap before buffering when present.

### Proof of Concept
1. Attacker sets up an HTTPS server that returns HTTP 200 with a `Transfer-Encoding: chunked` response that never ends (or a multi-GB body).
2. Attacker sends the victim a URI: `obyte:data?app=definition&definition=https://attacker.example/defs&address=...` (or embeds it in a payment/textcoin/chat link).
3. Victim's wallet calls `uri.parseUri()` on the received string, which detects `app === 'definition'` and a `definition` value starting with `https://`, invoking `fetchUrl(definition, cb)`.
4. `fetchUrl`'s `resp.on('data', ...)` handler keeps appending chunks to `data` indefinitely since there is no size cap, growing process memory until the process runs out of memory and crashes. [5](#0-4) [6](#0-5)

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
