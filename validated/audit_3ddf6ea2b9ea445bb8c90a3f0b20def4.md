### Title
Unvalidated remote definition fetch in payment-URI "definition" data request allows a spoofed AA/address definition to be posted to the network - (File: uri.js)

### Summary
`parseUri()` in `uri.js` handles `obyte:data?app=definition&definition=...` deep links. When the `definition` field starts with `https://`, the code fetches that URL and blindly substitutes the returned HTTP response body as the definition, without any binding between the fetched content and a previously-committed hash (chash) or the address the user believes they are interacting with. [1](#0-0) 

This mirrors the CVE-2023-41898 bug class: an app resolves an attacker-influenceable pointer (URL) into content that is then treated as trusted/structured input without validating that the fetched content matches what was expected, enabling substitution of arbitrary attacker-controlled data for what the user thinks they are loading.

### Finding Description
`parseUri` is the single entry point ocore-based wallets use to interpret `obyte:`/`byteball:` links (e.g. scanned QR codes, deep links, pasted text). For the `data` sub-type with `app=definition`, the code takes the `definition` query parameter as-is:

```js
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
``` [1](#0-0) 

There is no check that:
- the URL is HTTPS-pinned to a specific expected host/registry,
- the returned `response` is validated to be a well-formed `['sig'|'and'|'or'|...]` address-definition array before being handed back as `objRequest.definition`,
- the resulting definition's chash matches any address that the calling UI/CLI expected.

The only place that later re-validates arbitrary attacker-influenced definitions before they are trusted and inserted into local storage is `wallet_defined_by_addresses.js`'s `handleNewSharedAddress`, which explicitly recomputes the chash and rejects mismatches:
```js
var addr = objectHash.getChash160(body.definition);
...
if (body.address !== addr)
    return callbacks.ifError("definition doesn't match its c-hash");
``` [2](#0-1) 

The `uri.js` "definition" data-request path performs no equivalent chash binding — it treats the value fetched from an arbitrary attacker-supplied `https://` URL as authoritative content and forwards it straight to `callbacks.ifOk(objRequest)`, which downstream UI code typically uses to pre-fill a "post definition" or "post data" action for the user to confirm and sign. Because the content comes from a remote server that the attacker fully controls (and can also serve different content depending on requester, time, or after the link has already been reviewed/shared — a classic TOCTOU/bait-and-switch), the attacker can supply a completely different oscript/address definition than what the victim expects (e.g. shown in a preview or matched against a QR context), and the wallet will use it verbatim as `data`/`definition` payload content to be posted on-chain, or (if the flow later composes an "address definition"/AA definition unit) as the actual structure being deployed.

### Impact Explanation
If a victim scans/opens such a `definition` data-URI link and proceeds to sign/post the resulting message, they can be induced into publishing on the DAG a definition object they never actually reviewed (a bait-and-switch: the URL can serve benign content when previewed and malicious content when finally fetched at signing time, or serve different content to different requesters). If the flow that consumes this parsed request composes an actual `app: 'definition'` unit or a shared/multisig address definition based on the fetched content without a chash cross-check (unlike `handleNewSharedAddress`), it can result in the victim unknowingly authorizing an address/AA definition whose control conditions (`sig`, `and`/`or`, `address` fields) were swapped by the attacker — leading to loss of funds sent to that address, or deployment of an AA whose behavior differs from what the user was shown. This satisfies the "unauthorized spending" / "AA fund loss" impact bar.

### Likelihood Explanation
Requires user interaction (opening a crafted link/QR — matches CVE-2023-41898's `UI:R` requirement) and requires the consuming UI/CLI code to not perform independent chash validation before signing. The `fetchUrl` call happens with no host allow-list and no TLS pinning, so any attacker who can get a victim to open such a link (chat, QR poster, forum) controls the definition content returned at the exact moment of the request.

### Recommendation
- Require the `definition` data-request to include an expected chash/hash of the definition (similar to how `definition` app in payment/asset flows bind `address = chash(definition)`), and verify `objectHash.getChash160(response) === expected_chash` before calling `callbacks.ifOk`.
- Restrict `fetchUrl` targets or require pinned content hashes (e.g., `sha256=` parameter) so the fetched bytes can be verified independent of server behavior.
- Ensure any UI code consuming `type: 'data', app: 'definition'` results always re-validates the definition structure and its correspondence to any previously-displayed address before requesting a user signature.

### Proof of Concept
1. Attacker hosts `https://attacker.example/def.json` returning a benign-looking definition, e.g. `["sig", {"pubkey": "<attacker-controlled-benign-preview>"}]`.
2. Attacker sends victim a link: `obyte:data?app=definition&definition=https://attacker.example/def.json`.
3. Victim's wallet calls `parseUri`, which calls `fetchUrl` and gets the benign definition for preview/confirmation.
4. At the moment the victim confirms/signs, attacker's server is switched (by IP/time/User-Agent) to return a malicious definition, e.g. `["sig", {"pubkey": "<attacker key>"}]` replacing what was shown, or an `["and", ...]` structure altering spending conditions.
5. The wallet — since `uri.js` performs no chash binding on this path — accepts the new response as `objRequest.definition` and proceeds to build/sign a unit based on it, resulting in the victim authorizing a definition they never actually reviewed. [1](#0-0) [3](#0-2)

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

**File:** wallet_defined_by_addresses.js (L377-391)
```javascript
// {address: "BASE32", definition: [...], signers: {...}}
function handleNewSharedAddress(body, callbacks){
	if (!ValidationUtils.isArrayOfLength(body.definition, 2))
		return callbacks.ifError("invalid definition");
	if (typeof body.signers !== "object" || Object.keys(body.signers).length === 0)
		return callbacks.ifError("invalid signers");
	try {
		var addr = objectHash.getChash160(body.definition);
	}
	catch (e) {
		return callbacks.ifError("invalid definition: " + e);
	}
	if (body.address !== addr)
		return callbacks.ifError("definition doesn't match its c-hash");
	for (var signing_path in body.signers){
```
