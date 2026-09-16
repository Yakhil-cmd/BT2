## Analog Found: SSRF via unvalidated user-supplied URL in `uri.js`'s definition-URI fetch

### Title
Missing URL/host validation in `fetchUrl()` used for `obyte:` payment-request URIs enables SSRF - (File: `uri.js`)

### Summary
When `uri.js`'s `parseUri()` parses a `data`-type URI whose `app` parameter is `definition`, and the `definition` value starts with `https://`, it directly passes that attacker-controlled string to `fetchUrl()`, which performs a raw `https.get(url, ...)` with no validation of the host, IP, or network range. [1](#0-0) [2](#0-1) 

### Finding Description
`parseUri()` is the entry point used by wallet clients to interpret `byteball:`/`obyte:` deep links, e.g. shared via chat messages, QR codes, or "pay to" links from any counterparty. For the `data` app type with `app=definition`, if `assocParams.definition` (fully attacker-controlled, taken straight from the URI query string with only `decodeURIComponent` applied) begins with `https://`, the code calls:

```js
if (definition.substr(0, 8) === 'https://') {
    return fetchUrl(definition, function (err, response) {
        ...
        assocParams.definition = response;
        callbacks.ifOk(objRequest);
    });
}
``` [3](#0-2) 

`fetchUrl()` itself does no validation of the target host/IP whatsoever — it simply does `https.get(url, ...)` and returns whatever it receives:

```js
function fetchUrl(url, cb) {
	var https = require('https');
	...
	try {
		https.get(url, function (resp) {
			if (resp.statusCode !== 200)
				return returnError("non-200 response while trying to fetch " + url);
			...
``` [4](#0-3) 

There is no check against internal/private IP ranges (e.g., `127.0.0.1`, `169.254.169.254` for cloud metadata, `10.0.0.0/8`, etc.), no protocol/host allowlist, and no restriction to a specific domain. Unlike other parts of `uri.js` that carefully validate addresses, hub URLs (`hub.match(/[^\w\.:-]/)`), amounts, and assets, the `definition` URL branch has no equivalent hardening — this is the same class of bug as the reported CWE-918 (missing IP/network-range validation on a user-supplied reference that triggers an outbound request).

### Impact Explanation
Any party able to hand a victim wallet a URI (a correspondent/paired device sending a chat "pay" link, a QR code, or a web link) can force the victim's node/wallet process to make an outbound HTTPS request to an arbitrary internal address. This enables:
- Internal network/service enumeration and port-scanning from the victim's environment (status code and error messages, e.g. "non-200 response ... " vs "connection aborted ...", leak reachability/behavior of internal hosts).
- Limited information disclosure, since the fetched body is placed into `assocParams.definition` and surfaced back to the requesting UI flow.
- Potential DoS, since there is no timeout on the `https.get` call and a malicious/slow-responding endpoint (or an endless internal stream) can hang the request indefinitely.

### Likelihood Explanation
Likelihood is high: constructing a malicious `obyte:data?app=definition&definition=https://169.254.169.254/...`-style URI requires no special privileges and can be delivered to a victim via any channel that normally carries these payment-request links (chat text, QR codes). The vulnerable code path executes automatically as soon as the URI is parsed, with no user confirmation of the destination host before the request fires.

### Recommendation
Before calling `fetchUrl`, validate the parsed hostname against a blocklist of private/loopback/link-local/metadata IP ranges (and resolve DNS to check the resolved IP too, to prevent DNS-rebinding), restrict the scheme strictly to `https:`, and/or require the host to be on an allowlist of known trusted definition-hosting domains. Additionally, add a request timeout to `fetchUrl()` to bound resource usage.

### Proof of Concept
1. Craft a URI: `obyte:data?app=definition&definition=https%3A%2F%2F169.254.169.254%2Flatest%2Fmeta-data%2F`
2. Send it to a victim via chat/QR/link; when the wallet calls `uri.parseUri()` on it, `fetchUrl()` performs `https.get('https://169.254.169.254/latest/meta-data/', ...)` with no validation, disclosing metadata-service/internal-network responses back through the `ifOk`/`ifError` callback flow. [5](#0-4) [2](#0-1)

### Citations

**File:** uri.js (L104-136)
```javascript
	// pay to address or send data
	var arrParts = value.split('?');
	if (arrParts.length > 2)
		return callbacks.ifError("too many question marks");
	var main_part = decodeURIComponent(arrParts[0]);
	var query_string = arrParts[1];

	if (main_part === 'data') {
		if (!query_string)
			return callbacks.ifError("data without query string");
		var assocParams = parseQueryString(query_string);
		objRequest = assocParams;
		objRequest.type = 'data';
		var app = assocParams.app;
		if (!['data', 'temp_data', 'data_feed', 'attestation', 'profile', 'poll', 'vote', 'definition', 'text', 'system_vote', 'system_vote_count'].includes(app))
			return callbacks.ifError("invalid app: " + app);
		if (app === 'attestation' && !ValidationUtils.isValidAddress(assocParams.address))
			return callbacks.ifError("invalid attested address: "+assocParams.address);
		if (app === 'vote' && !ValidationUtils.isValidBase64(assocParams.unit, constants.HASH_LENGTH))
			return callbacks.ifError("invalid poll unit: " + assocParams.unit);
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
